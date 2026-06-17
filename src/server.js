require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const multer = require('multer');

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});
const { ObjectId } = mongoose.Types;

// Required behind Railway/Render proxies so rate limiting and client IP detection work correctly.
const trustProxyEnv = process.env.TRUST_PROXY;
const trustProxy =
  trustProxyEnv === undefined
    ? 1
    : trustProxyEnv === 'true'
      ? true
      : trustProxyEnv === 'false'
        ? false
        : Number.isNaN(Number(trustProxyEnv))
          ? trustProxyEnv
          : Number(trustProxyEnv);
app.set('trust proxy', trustProxy);
app.disable('etag');

app.use(helmet());
const corsOriginEnv = (process.env.CORS_ORIGIN || '').trim();
const corsOrigins = corsOriginEnv
  ? corsOriginEnv
      .split(',')
      .map((origin) => origin.trim())
      .filter(Boolean)
  : null;
app.use(
  cors({
    origin: corsOrigins || true,
    credentials: true,
  })
);
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  next();
});
app.use(morgan('dev'));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 40),
  standardHeaders: true,
  legacyHeaders: false,
});

const port = Number(process.env.PORT) || 4000;
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;
const aiDetectionUrl = (process.env.AI_DETECTION_URL || '').trim();
const allowAiFallback = String(process.env.ALLOW_AI_FALLBACK || 'true').toLowerCase() !== 'false';
const vlmApiUrl = (process.env.VLM_API_URL || '').replace(/\/+$/, '');
const gradingApiUrl = (process.env.GRADING_API_URL || '').replace(/\/+$/, '');
const maxPipelineRetries = Number(process.env.PIPELINE_MAX_RETRIES || 3);

const buildServiceUrl = (baseUrl, defaultPath) => {
  if (!baseUrl) return '';
  try {
    const url = new URL(baseUrl);
    const cleanPath = url.pathname.replace(/\/+$/, '');
    url.pathname = cleanPath && cleanPath !== '' ? cleanPath : defaultPath;
    return url.toString();
  } catch {
    return baseUrl;
  }
};

const aiDetectionEndpoint = buildServiceUrl(aiDetectionUrl, '/predict');

const okUser = (u) => ({
  id: String(u._id),
  name: u.name,
  email: u.email,
  role: u.role,
});

const getDbOrFail = () => {
  const db = mongoose.connection.db;
  if (!db) {
    const err = new Error('Database not connected');
    err.status = 503;
    throw err;
  }
  return db;
};

const sendApiError = (res, status, code, message, details = null) =>
  res.status(status).json({
    error: {
      code,
      message,
      details,
    },
  });

const parsePagination = (query = {}) => {
  const page = Math.max(1, Number(query.page) || 1);
  const limit = Math.min(100, Math.max(1, Number(query.limit) || 20));
  const skip = (page - 1) * limit;
  return { page, limit, skip };
};

const buildPaginatedResponse = ({ items, total, page, limit }) => ({
  items,
  pagination: {
    page,
    limit,
    total,
    totalPages: Math.max(1, Math.ceil(total / limit)),
  },
});

const logAudit = async ({ actor, action, targetType, targetId, meta = {} }) => {
  try {
    const db = getDbOrFail();
    await db.collection('audit_logs').insertOne({
      actorId: actor?.id || null,
      actorEmail: actor?.email || '',
      actorRole: actor?.role || '',
      action,
      targetType,
      targetId,
      meta,
      createdAt: new Date(),
    });
  } catch (err) {
    console.error(`[audit] action=${action} target=${targetType}:${targetId} error=${err.message}`);
  }
};

const ensureIndexes = async () => {
  const db = getDbOrFail();
  await Promise.all([
    db.collection('users').createIndex({ email: 1 }, { unique: true, name: 'users_email_unique' }),
    db.collection('assignments').createIndex({ doctorId: 1 }, { name: 'assignments_doctorId' }),
    db.collection('assignments').createIndex(
      { doctorEmail: 1 },
      { name: 'assignments_doctorEmail' }
    ),
    db.collection('submissions').createIndex(
      { assignmentId: 1 },
      { name: 'submissions_assignmentId' }
    ),
    db.collection('submissions').createIndex({ studentId: 1 }, { name: 'submissions_studentId' }),
    db.collection('course_materials').createIndex(
      { doctorId: 1, course: 1 },
      { name: 'course_materials_doctor_course' }
    ),
    db.collection('audit_logs').createIndex({ createdAt: -1 }, { name: 'audit_logs_createdAt_desc' }),
  ]);
};

const parseObjectId = (id) => {
  if (!ObjectId.isValid(id)) return null;
  return new ObjectId(id);
};

const idToString = (value) => {
  if (value === null || value === undefined) return '';
  try {
    return String(value);
  } catch (_err) {
    return '';
  }
};

const isSameId = (a, b) => idToString(a) && idToString(a) === idToString(b);

const userIdAlternatives = (userId) => {
  const alt = [userId];
  const asObjectId = parseObjectId(userId);
  if (asObjectId) alt.push(asObjectId);
  return alt;
};

const normalizeEmail = (email) => String(email || '').trim().toLowerCase();

const doctorOwnershipFilter = (user) => {
  if (!user || user.role === 'admin') return {};
  const doctorEmail = normalizeEmail(user.email);
  const byDoctorId = { doctorId: { $in: userIdAlternatives(user.id) } };
  if (!doctorEmail) return byDoctorId;
  return {
    $or: [byDoctorId, { doctorEmail }],
  };
};

const pickUploadedFile = (files = []) => {
  if (!Array.isArray(files) || files.length === 0) return null;
  const preferred = files.find((f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname));
  return preferred || files[0] || null;
};

const pickUploadedFiles = (files = []) => {
  if (!Array.isArray(files) || files.length === 0) return [];
  const preferred = files.filter((f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname));
  return preferred.length ? preferred : files;
};

const fileMetadata = (file) => ({
  originalName: file.originalname,
  mimeType: file.mimetype,
  size: file.size,
});

const validateUploadFiles = (files = []) => {
  if (!files.length) return { ok: false, message: 'Missing upload file' };
  for (const file of files) {
    const validType = validateUploadFileType(file);
    if (!validType.ok) return validType;
  }
  return { ok: true };
};

const ensureDoctorAssignmentAccess = (assignment, user) => {
  if (!assignment) return { ok: false, status: 404, message: 'Assignment not found' };
  if (user.role === 'admin') return { ok: true };
  if (user.role === 'doctor') {
    const isOwnerById = isSameId(assignment.doctorId, user.id);
    const isOwnerByEmail =
      normalizeEmail(assignment.doctorEmail) &&
      normalizeEmail(assignment.doctorEmail) === normalizeEmail(user.email);
    if (isOwnerById || isOwnerByEmail) return { ok: true };
  }
  return { ok: false, status: 403, message: 'Forbidden' };
};

const getSubmissionAssignmentObjectId = (submission) =>
  submission && submission.assignmentId instanceof ObjectId
    ? submission.assignmentId
    : parseObjectId(submission?.assignmentId);

const mapStudentAssignmentStatus = (submission) => {
  if (!submission) return 'not_submitted';
  if (submission.status === 'graded' || typeof submission.score === 'number') return 'ai_graded';
  if (submission.status === 'submitted') return 'submitted';
  return 'submitted';
};

const mapStudentExamStatus = (submission) => {
  if (!submission) return 'not_started';
  if (submission.status === 'graded' || typeof submission.score === 'number') return 'finished';
  return 'in_progress';
};

const getAssignmentType = (assignment) => assignment?.type || assignment?.kind || 'exam';
const getAssignmentStatus = (assignment) =>
  new Date(assignment?.dueDate || 0) >= new Date() ? 'open' : 'closed';
const isExamAssignment = (assignment) => getAssignmentType(assignment) === 'exam';
const assignmentOnlyFilter = { $nor: [{ type: 'exam' }, { kind: 'exam' }] };
const examOnlyFilter = { $or: [{ type: 'exam' }, { kind: 'exam' }] };
const andFilters = (...filters) => {
  const clean = filters.filter((filter) => filter && Object.keys(filter).length > 0);
  if (!clean.length) return {};
  if (clean.length === 1) return clean[0];
  return { $and: clean };
};
const isPublishedForStudents = (assignment) => Boolean(assignment?.resultsPublished);
const getAssignmentTotalMark = (assignment, fallback = 100) => Number(assignment?.totalMark ?? fallback);

const getSubmissionPercentage = (submission, assignment) => {
  const score = getSubmissionScore(submission);
  const totalMark = getAssignmentTotalMark(assignment, 100);
  if (score === null || !Number.isFinite(totalMark) || totalMark <= 0) return null;
  return Number(((score / totalMark) * 100).toFixed(2));
};

const getSubmissionResultStatus = (submission, assignment) => {
  const percentage = getSubmissionPercentage(submission, assignment);
  if (percentage === null) return null;
  return percentage >= 50 ? 'passed' : 'failed';
};

const allowedUploadMimeTypes = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'application/pdf',
]);

const validateUploadFileType = (file) => {
  if (!file) return { ok: false, message: 'Missing upload file' };
  if (!allowedUploadMimeTypes.has(String(file.mimetype || '').toLowerCase())) {
    return {
      ok: false,
      message: `Unsupported file type '${file.mimetype}'. Allowed: jpeg, png, webp, pdf`,
    };
  }
  return { ok: true };
};

const buildLinkedQuestionsForGrading = (assignment = {}, submission = {}, options = {}) => {
  const materials = Array.isArray(options.materials) ? options.materials : [];
  const materialText = materials
    .map((m) => [m.title, m.description, m.materialText].filter(Boolean).join('\n'))
    .filter(Boolean)
    .join('\n\n');
  if (Array.isArray(submission.linked_questions) && submission.linked_questions.length) {
    return submission.linked_questions.map((q) => ({
      ...q,
      course_material: q.course_material || materialText,
      materials,
    }));
  }

  const answers = Array.isArray(submission.answers) ? submission.answers : [];
  const answerMap = new Map(answers.map((a) => [idToString(a.question_id), a]));
  const questions =
    Array.isArray(assignment.questions) && assignment.questions.length ? assignment.questions : [];

  return questions.map((q, index) => {
    const qid = q.id ?? index + 1;
    const answer = answerMap.get(idToString(qid));
    const studentAnswer =
      answer?.answer || (questions.length === 1 ? submission.answerText || '' : 'na') || 'na';
    return {
      question_id: qid,
      type: q.type || 'essay',
      question: q.text || '',
      options: Array.isArray(q.options) ? q.options : [],
      student_answer: studentAnswer,
      correct_answer: q.correct_answer || '',
      model_answer: q.model_answer || q.modelAnswer || '',
      max_score: q.points || assignment.totalMark || 1,
      course_material: materialText,
      materials,
      attempted: studentAnswer !== 'na' && studentAnswer !== 'unclear' && Boolean(String(studentAnswer).trim()),
      needs_manual_review: studentAnswer === 'unclear',
    };
  });
};

const getCourseIdForPipeline = (assignment = {}) =>
  assignment.course_id || assignment.courseId || assignment.course || assignment.subject || null;

const normalizeCourseName = (course) => String(course || '').trim();

const isNotAttemptedAnswer = (value) => {
  const text = String(value ?? '').trim().toLowerCase();
  return !text || ['na', 'n/a', 'not answered', 'not_attempted', 'not attempted'].includes(text);
};

const normalizeReviewAnswer = (value) => (isNotAttemptedAnswer(value) ? '' : String(value ?? '').trim());

const sanitizeGradeResultForReview = (item = {}) => {
  const studentAnswer = getItemStudentAnswer(item);
  const score = getItemScore(item);
  const maxScore = firstFiniteNumber(item.max_score, item.maxScore, item.outOf, item.points);
  const attempted = !isNotAttemptedAnswer(studentAnswer);
  const isCorrect = attempted && score !== null && maxScore !== null ? score >= maxScore : false;
  return {
    ...item,
    student_answer: normalizeReviewAnswer(studentAnswer),
    studentAnswer: normalizeReviewAnswer(studentAnswer),
    correctAnswer: item.correct_answer ?? item.correctAnswer ?? '',
    gradingMode: item.grading_mode || item.gradingMode || '',
    justification: item.justification || item.feedback || item.reasoning || '',
    maxScore,
    needsManualReview: Boolean(item.needs_manual_review ?? item.needsManualReview),
    aiDetection: item.ai_detection ?? item.aiDetection ?? null,
    answerStatus: attempted ? 'answered' : 'not_attempted',
    isCorrect,
    resultStatus: !attempted ? 'not_attempted' : isCorrect ? 'correct' : 'incorrect',
  };
};

const buildMaterialSummary = (materialDocs = []) =>
  materialDocs.map((doc) => ({
    id: idToString(doc._id),
    course: doc.course,
    title: doc.title || doc.course,
    description: doc.description || '',
    materialText: doc.materialText || '',
    files: Array.isArray(doc.files) ? doc.files : [],
    gradingPayload: doc.gradingPayload || null,
    uploadedAt: doc.createdAt || doc.uploadedAt || null,
  }));

const buildIdMatchValues = (value) => {
  const values = [];
  if (value !== undefined && value !== null && value !== '') values.push(value);
  const asString = idToString(value);
  if (asString) values.push(asString);
  const asObjectId = parseObjectId(asString);
  if (asObjectId) values.push(asObjectId);
  return [...new Map(values.map((v) => [idToString(v) || String(v), v])).values()];
};

const looksLikeEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());

const pickDisplayName = (...values) => {
  const cleanValues = values.map((v) => String(v || '').trim()).filter(Boolean);
  return cleanValues.find((v) => !looksLikeEmail(v)) || cleanValues[0] || 'Student';
};

const getStudentIdentityForSubmission = async (db, submission = {}) => {
  const filters = [
    ...buildIdMatchValues(submission.studentId).map((studentId) => ({ _id: studentId })),
    ...(submission.studentEmail ? [{ email: normalizeEmail(submission.studentEmail) }] : []),
  ];
  const user = filters.length ? await db.collection('users').findOne({ $or: filters }) : null;
  const email = submission.studentEmail || user?.email || '';
  return {
    id: idToString(submission.studentId || user?._id),
    name: pickDisplayName(submission.studentName, user?.name, email),
    email,
  };
};

const getCourseMaterialsForAssignment = async (db, assignment = {}) => {
  const course = normalizeCourseName(getCourseIdForPipeline(assignment));
  if (!course) return [];
  const ownerFilters = [
    ...buildIdMatchValues(assignment.doctorId).map((doctorId) => ({ doctorId })),
    ...(assignment.doctorEmail ? [{ doctorEmail: assignment.doctorEmail }] : []),
  ];
  const query = {
    course,
    ...(ownerFilters.length ? { $or: ownerFilters } : {}),
  };
  return db.collection('course_materials').find(query).sort({ createdAt: -1 }).toArray();
};

const normalizePercentValue = (value) => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value <= 1 ? Number((value * 100).toFixed(2)) : Number(value.toFixed(2));
};

const normalizeAiDetectionResult = (payload = {}) => {
  const aiPercentage =
    normalizePercentValue(payload.ai_percentage) ??
    normalizePercentValue(payload.aiPercentage) ??
    normalizePercentValue(payload.aiScore) ??
    normalizePercentValue(payload.score) ??
    0;
  const humanPercentage =
    normalizePercentValue(payload.human_percentage) ??
    normalizePercentValue(payload.humanPercentage) ??
    Number((100 - aiPercentage).toFixed(2));

  return {
    ...payload,
    ai_percentage: aiPercentage,
    human_percentage: humanPercentage,
    decision: payload.decision || payload.prediction || (aiPercentage >= 70 ? 'rejected' : 'accepted'),
  };
};

const normalizeGradingResult = (payload = {}) => {
  const breakdown = Array.isArray(payload.grade_results)
    ? payload.grade_results
    : Array.isArray(payload.grades)
      ? payload.grades
      : Array.isArray(payload.results)
        ? payload.results
        : Array.isArray(payload.items)
          ? payload.items
          : [];
  const totalScore =
    typeof payload.total_score === 'number'
      ? payload.total_score
      : typeof payload.totalScore === 'number'
        ? payload.totalScore
        : typeof payload.score === 'number'
          ? payload.score
          : null;

  return {
    ...payload,
    total_score: totalScore,
    grade_results: breakdown,
    feedback: payload.feedback || payload.justification || payload.summary || '',
    grading_mode: payload.grading_mode || payload.gradingMode || payload.source || 'pipeline',
  };
};

const firstFiniteNumber = (...values) => {
  for (const value of values) {
    const num = typeof value === 'number' ? value : Number(value);
    if (Number.isFinite(num)) return num;
  }
  return null;
};

const normalizeSimilarityValue = (value) => {
  const num = firstFiniteNumber(value);
  if (num === null) return null;
  return normalizePercentValue(num);
};

const getQuestionResultKey = (item = {}) =>
  idToString(
    item.question_id ??
      item.questionId ??
      item.question_number ??
      item.questionNumber ??
      item.id ??
      item.qid
  );

const getItemScore = (item = {}) =>
  firstFiniteNumber(
    item.score,
    item.awarded_score,
    item.awardedScore,
    item.grade,
    item.mark,
    item.marks
  );

const getItemSimilarity = (item = {}) =>
  normalizeSimilarityValue(
    item.similarity ??
      item.similarity_score ??
      item.similarityScore ??
      item.semantic_similarity ??
      item.semanticSimilarity ??
      item.match_percentage ??
      item.matchPercentage
  );

const getItemQuestionText = (item = {}) =>
  String(
    item.question ??
      item.question_text ??
      item.questionText ??
      item.prompt ??
      item.text ??
      ''
  ).trim();

const normalizeQuestionTextKey = (value) =>
  String(value || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[^\p{L}\p{N}\s]/gu, '')
    .trim();

const getItemStudentAnswer = (item = {}) =>
  String(
    item.student_answer ??
      item.studentAnswer ??
      item.answer ??
      item.answer_text ??
      item.answerText ??
      item.response ??
      item.text ??
      ''
  ).trim();

const isNotAttemptedFeedback = (value) => {
  const text = String(value || '').trim().toLowerCase();
  return text.includes('question not attempted') || text.includes('not attempted');
};

const getSubmissionScore = (submission) => {
  if (!submission) return null;
  const directScore = firstFiniteNumber(submission.score, submission.total_score, submission.totalScore);
  if (directScore !== null) return directScore;
  const breakdown = Array.isArray(submission.scoreBreakdown) ? submission.scoreBreakdown : [];
  const scores = breakdown.map(getItemScore).filter((v) => v !== null);
  return scores.length ? Number(scores.reduce((sum, v) => sum + v, 0).toFixed(2)) : null;
};

const getSubmissionSimilarity = (submission) => {
  if (!submission) return null;
  const directSimilarity = getItemSimilarity(submission);
  if (directSimilarity !== null) return directSimilarity;
  const candidates = [
    ...(Array.isArray(submission.answers) ? submission.answers : []),
    ...(Array.isArray(submission.scoreBreakdown) ? submission.scoreBreakdown : []),
  ];
  const values = candidates.map(getItemSimilarity).filter((v) => v !== null);
  if (!values.length) return null;
  return Number((values.reduce((sum, v) => sum + v, 0) / values.length).toFixed(2));
};

const buildQuestionReviewItems = ({ assignment = {}, submission = {} }) => {
  const breakdown = Array.isArray(submission.scoreBreakdown) ? submission.scoreBreakdown : [];
  const questions = Array.isArray(assignment?.questions) && assignment.questions.length
    ? assignment.questions
    : breakdown.length
      ? breakdown.map((item, index) => ({
          id: item.question_id ?? item.questionId ?? item.id ?? index + 1,
          text: getItemQuestionText(item) || assignment?.assignmentText || assignment?.description || assignment?.title || 'Question',
          points: firstFiniteNumber(item.outOf, item.max_score, item.maxScore, assignment?.totalMark),
        }))
    : [
        {
          id: 1,
          text: assignment?.assignmentText || assignment?.description || 'Question',
          points: assignment?.totalMark || null,
        },
      ];
  const answers = Array.isArray(submission.answers) && submission.answers.length
    ? submission.answers
    : [
        {
          question_id: 1,
          answer: submission.answerText || '',
          score: getSubmissionScore(submission),
          similarity: getSubmissionSimilarity(submission),
        },
      ];
  const byAnswerQ = new Map(answers.map((a) => [getQuestionResultKey(a), a]));
  const byBreakdownQ = new Map(breakdown.map((b) => [getQuestionResultKey(b), b]));
  const byAnswerText = new Map(
    answers
      .map((a) => [normalizeQuestionTextKey(getItemQuestionText(a)), a])
      .filter(([key]) => key)
  );
  const byBreakdownText = new Map(
    breakdown
      .map((b) => [normalizeQuestionTextKey(getItemQuestionText(b)), b])
      .filter(([key]) => key)
  );

  return questions.map((q, index) => {
    const key = idToString(q.id ?? q.question_id ?? index + 1);
    const questionTextKey = normalizeQuestionTextKey(q.text || q.question || getItemQuestionText(q));
    const answer =
      byAnswerQ.get(key) ||
      byAnswerText.get(questionTextKey) ||
      byAnswerQ.get(idToString(index + 1)) ||
      answers[index] ||
      null;
    const result =
      byBreakdownQ.get(key) ||
      byBreakdownText.get(questionTextKey) ||
      byBreakdownQ.get(idToString(index + 1)) ||
      breakdown[index] ||
      {};
    const score = getItemScore(result) ?? getItemScore(answer || {});
    const similarity = getItemSimilarity(answer || {}) ?? getItemSimilarity(result) ?? getSubmissionSimilarity(submission);
    const maxScore = firstFiniteNumber(q.points, q.mark, q.marks, result.outOf, result.max_score, result.maxScore);
    const studentAnswer =
      getItemStudentAnswer(answer || {}) ||
      getItemStudentAnswer(result) ||
      (questions.length === 1 ? String(submission.answerText || '').trim() : '');
    const cleanedStudentAnswer = normalizeReviewAnswer(studentAnswer);
    const answerStatus = isNotAttemptedAnswer(studentAnswer) ? 'not_attempted' : 'answered';
    const isCorrect = answerStatus === 'answered' && score !== null && maxScore !== null ? score >= maxScore : false;
    const questionText =
      q.text ||
      q.question ||
      getItemQuestionText(result) ||
      getItemQuestionText(answer || {}) ||
      assignment?.assignmentText ||
      assignment?.description ||
      assignment?.title ||
      'Question';
    const rawFeedback = result.justification || answer?.feedback || result.feedback || result.reasoning || '';
    const feedback =
      answerStatus === 'answered' && isNotAttemptedFeedback(rawFeedback)
        ? 'Answer was extracted, but the grading service marked this question as not attempted. Needs manual review.'
        : rawFeedback;
    return {
      questionId: q.id ?? q.question_id ?? index + 1,
      question: questionText,
      studentAnswer: cleanedStudentAnswer,
      answer: cleanedStudentAnswer,
      correctAnswer: result.correct_answer ?? result.correctAnswer ?? q.correct_answer ?? q.correctAnswer ?? '',
      answerStatus,
      score,
      similarity,
      feedback,
      justification: feedback,
      gradingMode: result.grading_mode || result.gradingMode || submission.gradingSource || '',
      aiDetection: result.ai_detection ?? result.aiDetection ?? null,
      needsManualReview: Boolean(result.needs_manual_review ?? result.needsManualReview) ||
        (answerStatus === 'answered' && isNotAttemptedFeedback(rawFeedback)),
      maxScore,
      isCorrect,
      resultStatus: answerStatus === 'not_attempted' ? 'not_attempted' : isCorrect ? 'correct' : 'incorrect',
      status: score !== null ? 'ai_graded' : similarity !== null ? 'similarity_checked' : 'submitted',
    };
  });
};

const appendFilesToForm = (form, files = [], fieldName = 'images') => {
  for (const file of files) {
    form.append(fieldName, new Blob([file.buffer], { type: file.mimetype }), file.originalname);
  }
};

const normalizeVlmExamPayload = (payload = {}) => {
  const questions = Array.isArray(payload.questions)
    ? payload.questions
    : Array.isArray(payload.exam?.questions)
      ? payload.exam.questions
      : [];
  return {
    ...payload,
    questions: questions.map((q, index) => ({
      id: q.id ?? q.question_id ?? q.questionId ?? index + 1,
      text: q.text || q.question || q.question_text || '',
      type: q.type || 'essay',
      options: Array.isArray(q.options) ? q.options : [],
      points: firstFiniteNumber(q.points, q.max_score, q.maxScore) ?? 1,
      correct_answer: q.correct_answer || q.correctAnswer || '',
      model_answer: q.model_answer || q.modelAnswer || '',
    })),
  };
};

const normalizeVlmAnswersPayload = (payload = {}) => {
  const answers = Array.isArray(payload.answers)
    ? payload.answers
    : Array.isArray(payload.items)
      ? payload.items
      : [];
  return {
    ...payload,
    answers: answers.map((a, index) => ({
      question_id: a.question_id ?? a.questionId ?? a.id ?? index + 1,
      answer: a.answer || a.student_answer || a.studentAnswer || a.text || '',
    })),
  };
};

const hasUsableVlmQuestions = (payload = {}) =>
  Array.isArray(payload.questions) &&
  payload.questions.some((q) => String(q.text || q.question || q.question_text || '').trim());

const buildVlmQuestionExtractionError = (vlmExam) => {
  if (!vlmApiUrl) {
    return { status: 503, message: 'VLM_API_URL is not configured, so exam questions cannot be extracted.' };
  }
  if (!vlmExam) {
    return { status: 502, message: 'VLM did not return a response while extracting exam questions.' };
  }
  if (vlmExam.error) {
    return { status: 502, message: 'VLM failed to extract exam questions.', details: vlmExam.error };
  }
  if (!hasUsableVlmQuestions(vlmExam)) {
    return {
      status: 422,
      message:
        'VLM could not extract any questions from this file. Upload a clearer exam/assignment paper image or PDF.',
      details: vlmExam,
    };
  }
  return null;
};

const callVlmProcessExam = async (files = []) => {
  if (!vlmApiUrl || !files.length) return null;
  const form = new FormData();
  appendFilesToForm(form, files);
  const response = await fetch(`${vlmApiUrl}/process-exam`, { method: 'POST', body: form });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`vlm process-exam failed with ${response.status}: ${JSON.stringify(payload)}`);
  return normalizeVlmExamPayload(payload);
};

const callVlmProcessAnswers = async ({ files = [], questions = [] }) => {
  if (!vlmApiUrl || !files.length || !questions.length) return null;
  const form = new FormData();
  appendFilesToForm(form, files);
  form.append('questions', JSON.stringify(questions));
  const response = await fetch(`${vlmApiUrl}/process-answers`, { method: 'POST', body: form });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`vlm process-answers failed with ${response.status}: ${JSON.stringify(payload)}`);
  return normalizeVlmAnswersPayload(payload);
};

const callVlmLink = async ({ exam, answers }) => {
  if (!vlmApiUrl || !exam?.questions?.length || !answers?.answers?.length) return null;
  const response = await fetch(`${vlmApiUrl}/link`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ exam, answers }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`vlm link failed with ${response.status}: ${JSON.stringify(payload)}`);
  return Array.isArray(payload) ? payload : Array.isArray(payload.linked_questions) ? payload.linked_questions : null;
};

const runPipelineStepWithRetry = async ({ submissionId, stepName, fn, maxRetries }) => {
  let lastError = null;
  for (let attempt = 1; attempt <= maxRetries; attempt += 1) {
    try {
      const result = await fn();
      return { ok: true, result, attempts: attempt };
    } catch (err) {
      lastError = err;
      console.error(
        `[pipeline] step=${stepName} submission_id=${submissionId} attempt=${attempt} error=${err.message}`
      );
    }
  }
  return { ok: false, error: lastError, attempts: maxRetries };
};

const runSubmissionPipeline = async ({ submissionId, uploadedFiles = [] }) => {
  const db = getDbOrFail();
  const _id = parseObjectId(submissionId);
  if (!_id) return;
  const submission = await db.collection('submissions').findOne({ _id });
  if (!submission) return;
  const assignmentId = getSubmissionAssignmentObjectId(submission);
  const assignment = assignmentId ? await db.collection('assignments').findOne({ _id: assignmentId }) : null;
  let pipelineSubmission = { ...submission };
  const retryCap = Number.isFinite(maxPipelineRetries) && maxPipelineRetries > 0 ? maxPipelineRetries : 3;

  await db.collection('submissions').updateOne(
    { _id },
    {
      $set: {
        pipelineStatus: 'processing',
        pipelineRetries: 0,
        pipelineStartedAt: new Date(),
        pipelineUpdatedAt: new Date(),
      },
    }
  );

  const steps = [];

  const assignmentQuestions = Array.isArray(assignment?.questions) ? assignment.questions : [];
  if (uploadedFiles.length && assignmentQuestions.length && vlmApiUrl) {
    const vlmStep = await runPipelineStepWithRetry({
      submissionId,
      stepName: 'vlm',
      maxRetries: retryCap,
      fn: async () => {
        const examPayload = normalizeVlmExamPayload({ questions: assignmentQuestions });
        const answersPayload = await callVlmProcessAnswers({
          files: uploadedFiles,
          questions: examPayload.questions,
        });
        const linkedQuestions = await callVlmLink({
          exam: examPayload,
          answers: answersPayload,
        });
        const extractedAnswerText = (answersPayload?.answers || [])
          .map((a) => a.answer)
          .filter(Boolean)
          .join('\n\n');
        return { examPayload, answersPayload, linkedQuestions, extractedAnswerText };
      },
    });
    steps.push({ step: 'vlm', ok: vlmStep.ok, attempts: vlmStep.attempts });
    if (vlmStep.ok) {
      const vlmResult = vlmStep.result || {};
      const updateFields = {
        vlmExam: vlmResult.examPayload,
        vlmAnswers: vlmResult.answersPayload,
        linked_questions: Array.isArray(vlmResult.linkedQuestions) ? vlmResult.linkedQuestions : [],
        answers: Array.isArray(vlmResult.answersPayload?.answers) ? vlmResult.answersPayload.answers : [],
        pipelineUpdatedAt: new Date(),
      };
      if (vlmResult.extractedAnswerText) {
        updateFields.answerText = vlmResult.extractedAnswerText;
      }
      await db.collection('submissions').updateOne({ _id }, { $set: updateFields });
      pipelineSubmission = {
        ...pipelineSubmission,
        ...updateFields,
      };
    } else {
      await db.collection('submissions').updateOne(
        { _id },
        {
          $set: {
            vlmError: vlmStep.error?.message || 'VLM failed',
            pipelineUpdatedAt: new Date(),
          },
        }
      );
    }
  } else {
    const missingQuestions = Boolean(uploadedFiles.length && !assignmentQuestions.length);
    steps.push({
      step: 'vlm',
      ok: false,
      skipped: true,
      reason: !vlmApiUrl
        ? 'vlm_not_configured'
        : !uploadedFiles.length
          ? 'no_submission_images'
          : 'no_assignment_questions',
    });
    if (missingQuestions) {
      await db.collection('submissions').updateOne(
        { _id },
        {
          $set: {
            status: 'needs_exam_questions',
            pipelineStatus: 'failed',
            pipelineError:
              'ASSIGNMENT_QUESTIONS_REQUIRED: Upload the assignment/exam paper first so VLM can extract questions before grading.',
            pipelineSteps: steps,
            pipelineUpdatedAt: new Date(),
          },
        }
      );
      return;
    }
  }

  const aiDetectionStep = await runPipelineStepWithRetry({
    submissionId,
    stepName: 'ai-detection',
    maxRetries: retryCap,
    fn: async () => {
      const text = String(pipelineSubmission.answerText || '').trim();
      if (!text) return { ai_percentage: 0, decision: 'unknown' };
      if (!aiDetectionEndpoint) return { ai_percentage: 0.12, decision: 'human_like', mock: true };
      const resp = await fetch(aiDetectionEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });
      if (!resp.ok) throw new Error(`ai-detection failed with ${resp.status}`);
      const payload = await resp.json();
      return normalizeAiDetectionResult(payload);
    },
  });
  steps.push({ step: 'ai-detection', ok: aiDetectionStep.ok, attempts: aiDetectionStep.attempts });
  if (!aiDetectionStep.ok) {
    await db.collection('submissions').updateOne(
      { _id },
      {
        $set: {
          pipelineStatus: 'failed',
          pipelineRetries: aiDetectionStep.attempts,
          pipelineError: `ai-detection: ${aiDetectionStep.error?.message || 'unknown error'}`,
          pipelineUpdatedAt: new Date(),
        },
      }
    );
    return;
  }

  const gradingStep = await runPipelineStepWithRetry({
    submissionId,
    stepName: 'grading',
    maxRetries: retryCap,
    fn: async () => {
      const totalMark = Number(assignment?.totalMark ?? 20);
      const courseId = getCourseIdForPipeline(assignment);
      const courseMaterials = assignment ? await getCourseMaterialsForAssignment(db, assignment) : [];
      const materialSummary = buildMaterialSummary(courseMaterials);
      const linkedQuestions = buildLinkedQuestionsForGrading(assignment, pipelineSubmission, {
        materials: materialSummary,
      });
      if (!linkedQuestions.length) {
        throw new Error('ASSIGNMENT_QUESTIONS_REQUIRED: No questions found for grading.');
      }
      const hasModelAnswer =
        linkedQuestions.some((q) => String(q.model_answer || '').trim()) ||
        Boolean(assignment?.modelAnswer || assignment?.modelAnswerText);
      const hasCourseMaterial = materialSummary.length > 0;
      const gradingStrategy = hasCourseMaterial && hasModelAnswer
        ? 'material_and_model_answer'
        : hasCourseMaterial
          ? 'course_material'
          : hasModelAnswer
            ? 'model_answer'
            : 'gemini_fallback';
      if (!gradingApiUrl) {
        const base = String(submission.answerText || '').length % Math.max(totalMark, 1);
        return {
          grades: [{ question_id: 1, score: base, outOf: totalMark }],
          total_score: base,
          feedback: 'Auto-graded (mock)',
          source: 'local-mock',
        };
      }
      const resp = await fetch(`${gradingApiUrl}/grade`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          course_id: courseId,
          course: courseId,
          linked_questions: linkedQuestions,
          materials: materialSummary,
          course_materials: materialSummary,
          has_course_material: hasCourseMaterial,
          has_model_answer: hasModelAnswer,
          grading_strategy: gradingStrategy,
        }),
      });
      if (!resp.ok) throw new Error(`grading failed with ${resp.status}`);
      return normalizeGradingResult(await resp.json());
    },
  });
  steps.push({ step: 'grading', ok: gradingStep.ok, attempts: gradingStep.attempts });
  if (!gradingStep.ok) {
    await db.collection('submissions').updateOne(
      { _id },
      {
        $set: {
          pipelineStatus: 'failed',
          pipelineRetries: gradingStep.attempts,
          pipelineError: `grading: ${gradingStep.error?.message || 'unknown error'}`,
          pipelineUpdatedAt: new Date(),
        },
      }
    );
    return;
  }

  const grading = normalizeGradingResult(gradingStep.result || {});
  const normalizedScore = typeof grading.total_score === 'number' ? grading.total_score : null;

  await db.collection('submissions').updateOne(
    { _id },
    {
      $set: {
        ai_score: aiDetectionStep.result.ai_percentage,
        ai_decision: aiDetectionStep.result.decision,
        score: normalizedScore,
        status: typeof normalizedScore === 'number' ? 'graded' : submission.status || 'submitted',
        scoreBreakdown: grading.grade_results,
        feedback: grading.feedback,
        gradingSource: grading.grading_mode,
        gradingCourse: getCourseIdForPipeline(assignment),
        gradingStrategy: grading.grading_strategy || grading.gradingStrategy || grading.grading_mode,
        pipelineStatus: 'completed',
        pipelineRetries: Math.max(aiDetectionStep.attempts, gradingStep.attempts),
        pipelineSteps: steps,
        pipelineCompletedAt: new Date(),
        pipelineUpdatedAt: new Date(),
      },
    }
  );
};

const auth = async (req, res, next) => {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Missing token' });
    const decoded = jwt.verify(token, jwtSecret);
    const db = getDbOrFail();
    const userId = parseObjectId(decoded.id);
    if (!userId) return res.status(401).json({ message: 'Invalid token user' });
    const user = await db.collection('users').findOne({ _id: userId });
    if (!user) return res.status(401).json({ message: 'User not found' });
    if (user.active === false) return res.status(403).json({ message: 'User is deactivated' });
    req.user = decoded;
    return next();
  } catch (_err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

const allowRoles =
  (...roles) =>
  (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        message: 'Role required',
        requiredRoles: roles,
        currentRole: req.user?.role || null,
      });
    }
    return next();
  };

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const unwrapFindOneAndUpdateResult = (result) => (result && result.value ? result.value : result);

const issueToken = (user) =>
  jwt.sign(
    { id: String(user._id), email: user.email, role: user.role, name: user.name },
    jwtSecret,
    { expiresIn: '7d' }
  );

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).max(200).required(),
  role: Joi.string().valid('student', 'doctor', 'admin').required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(1).required(),
});

const assignmentSchema = Joi.object({
  title: Joi.string().min(2).max(200).required(),
  description: Joi.string().allow('').default(''),
  assignmentText: Joi.string().allow('').default(''),
  totalMark: Joi.number().min(0).required(),
  dueDate: Joi.date().required(),
});

const doctorProfileUpdateSchema = Joi.object({
  department: Joi.string().trim().allow('').max(120).optional(),
  courses: Joi.array().items(Joi.string().trim().min(1).max(120)).max(50).optional(),
}).or('department', 'courses');

const studentProfileUpdateSchema = Joi.object({
  department: Joi.string().trim().allow('').max(120).optional(),
  courses: Joi.array().items(Joi.string().trim().min(1).max(120)).max(50).optional(),
}).or('department', 'courses');

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'flutter-backend-api' });
});

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    message: 'Backend is running',
    hint: 'Use /health to check status',
  });
});

app.get('/openapi.json', (_req, res) => {
  res.json({
    openapi: '3.0.0',
    info: { title: 'Fairmark Backend API', version: '1.0.0' },
    paths: {
      '/api/auth/register': { post: { summary: 'Register user (student/doctor/admin)' } },
      '/api/auth/login': { post: { summary: 'Login user and return JWT' } },
	      '/assignments': { post: { summary: 'Create assignment' }, get: { summary: 'List assignments' } },
	      '/submissions': { post: { summary: 'Create or update student submission' } },
	      '/submissions/{submissionId}/grade': { put: { summary: 'Override submission grade (doctor/admin)' } },
	      '/api/submissions/{submissionId}/grade': { put: { summary: 'Override submission grade (doctor/admin)' } },
	      '/grades/student': { get: { summary: 'Student grades list' } },
      '/grades/{assignmentId}/publish': { patch: { summary: 'Publish assignment results' } },
      '/admin/users': { get: { summary: 'List users (paginated)' } },
      '/admin/users/{id}/status': { patch: { summary: 'Activate/deactivate user' } },
      '/admin/analytics': { get: { summary: 'Platform analytics' } },
    },
  });
});

// Simple API version prefix compatibility: /api/v1/* -> /api/*
app.use('/api/v1', (req, _res, next) => {
  req.url = `/api${req.url}`;
  next();
});

const registerHandler = asyncRoute(async (req, res) => {
  const { value, error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.message });

  const db = getDbOrFail();
  const users = db.collection('users');
  const email = value.email.toLowerCase();
  const exists = await users.findOne({ email });
  if (exists) return res.status(409).json({ message: 'Email already registered' });

  const now = new Date();
  const doc = {
    name: value.name,
    email,
    role: value.role,
    passwordHash: await bcrypt.hash(value.password, 10),
    createdAt: now,
    updatedAt: now,
  };

  const result = await users.insertOne(doc);
  doc._id = result.insertedId;
  const token = issueToken(doc);
  return res.status(201).json({ token, user: okUser(doc) });
});

const loginHandler = asyncRoute(async (req, res) => {
  const { value, error } = loginSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.message });

  const db = getDbOrFail();
  const users = db.collection('users');
  const email = value.email.toLowerCase();
  const user = await users.findOne({ email });
  if (!user || !user.passwordHash) {
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  const ok = await bcrypt.compare(value.password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid email or password' });

  const token = issueToken(user);
  return res.json({ token, user: okUser(user) });
});

// Keep both route styles to avoid frontend 404s.
app.post('/api/auth/register', authRateLimiter, registerHandler);
app.post('/auth/register', authRateLimiter, registerHandler);
app.post('/api/auth/login', authRateLimiter, loginHandler);
app.post('/auth/login', authRateLimiter, loginHandler);

const createAssignmentHandler = asyncRoute(async (req, res) => {
    const { value, error } = assignmentSchema.validate(req.body, {
      allowUnknown: true,
      stripUnknown: true,
    });
    if (error) return res.status(400).json({ message: error.message });

    const db = getDbOrFail();
    const now = new Date();
    const doctorObjectId = parseObjectId(req.user.id);
    const actorUser = doctorObjectId ? await db.collection('users').findOne({ _id: doctorObjectId }) : null;
    const actorCourses = Array.isArray(actorUser?.courses) ? actorUser.courses.map((c) => String(c).trim()) : [];
    const requestedCourse = String(req.body.course || '').trim();
    const course =
      requestedCourse || (actorCourses.length === 1 ? actorCourses[0] : '');
    if (req.user.role === 'doctor' && actorCourses.length > 0 && !course) {
      return res.status(400).json({ message: 'course is required for doctor assignments' });
    }
    if (req.user.role === 'doctor' && actorCourses.length > 0 && course && !actorCourses.includes(course)) {
      return res.status(403).json({ message: 'Doctor can create assignments only for own courses' });
    }
    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    const assignmentTextRaw = String(
      req.body.assignmentText ?? req.body.assignment ?? req.body.text ?? ''
    ).trim();
    const assignmentText = assignmentTextRaw || value.assignmentText || '';
	    const doc = {
	      ...value,
	      type: 'assignment',
	      kind: 'assignment',
	      dueDate: new Date(value.dueDate),
      doctorId: doctorObjectId || req.user.id,
      doctorEmail: req.user.email,
      course,
      assignmentText,
      modelAnswer: uploaded
        ? {
            ...fileMetadata(uploaded),
            uploadedAt: now,
          }
        : null,
      modelAnswerFiles: uploadedFiles.map((file) => ({
        ...fileMetadata(file),
        uploadedAt: now,
      })),
      createdAt: now,
      updatedAt: now,
    };
    const result = await db.collection('assignments').insertOne(doc);
    doc._id = result.insertedId;
    return res.status(201).json(doc);
  });

app.post('/assignments', auth, allowRoles('doctor', 'admin'), upload.any(), createAssignmentHandler);
app.post(
  '/api/assignments',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  createAssignmentHandler
);

const createExamHandler = asyncRoute(async (req, res) => {
  const { value, error } = assignmentSchema.validate(req.body, {
    allowUnknown: true,
    stripUnknown: true,
  });
  if (error) return res.status(400).json({ message: error.message });

  const db = getDbOrFail();
  const now = new Date();
  const doctorObjectId = parseObjectId(req.user.id);
  const actorUser = doctorObjectId ? await db.collection('users').findOne({ _id: doctorObjectId }) : null;
  const actorCourses = Array.isArray(actorUser?.courses) ? actorUser.courses.map((c) => String(c).trim()) : [];
  const requestedCourse = String(req.body.course || '').trim();
  const course =
    requestedCourse || (actorCourses.length === 1 ? actorCourses[0] : '');
  if (req.user.role === 'doctor' && actorCourses.length > 0 && !course) {
    return res.status(400).json({ message: 'course is required for doctor exams' });
  }
  if (req.user.role === 'doctor' && actorCourses.length > 0 && course && !actorCourses.includes(course)) {
    return res.status(403).json({ message: 'Doctor can create exams only for own courses' });
  }
  const uploadedFiles = pickUploadedFiles(req.files);
  const uploaded = uploadedFiles[0] || null;
  const assignmentTextRaw = String(
    req.body.assignmentText ?? req.body.assignment ?? req.body.text ?? ''
  ).trim();
  const assignmentText = assignmentTextRaw || value.assignmentText || '';
  const doc = {
    ...value,
    type: 'exam',
    kind: 'exam',
    dueDate: new Date(value.dueDate),
    doctorId: doctorObjectId || req.user.id,
    doctorEmail: normalizeEmail(req.user.email),
    course,
    assignmentText,
    modelAnswer: uploaded
      ? {
          ...fileMetadata(uploaded),
          uploadedAt: now,
        }
      : null,
    modelAnswerFiles: uploadedFiles.map((file) => ({
      ...fileMetadata(file),
      uploadedAt: now,
    })),
    createdAt: now,
    updatedAt: now,
  };
  const result = await db.collection('assignments').insertOne(doc);
  doc._id = result.insertedId;
  return res.status(201).json(doc);
});

app.post('/exams', auth, allowRoles('doctor', 'admin'), upload.any(), createExamHandler);
app.post('/api/exams', auth, allowRoles('doctor', 'admin'), upload.any(), createExamHandler);

app.get(
  '/assignments',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const query =
      req.user.role === 'admin'
        ? {}
        : req.user.role === 'doctor'
          ? doctorOwnershipFilter(req.user)
          : {};
    const [docs, total] = await Promise.all([
      db.collection('assignments').find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('assignments').countDocuments(query),
    ]);
    return res.json(buildPaginatedResponse({ items: docs, total, page, limit }));
  })
);

app.get(
  '/exams',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const ownershipQuery =
      req.user.role === 'admin'
        ? {}
        : req.user.role === 'doctor'
          ? doctorOwnershipFilter(req.user)
          : {};
    const examTypeQuery = { $or: [{ type: 'exam' }, { kind: 'exam' }] };
    const query =
      Object.keys(ownershipQuery).length > 0
        ? { $and: [ownershipQuery, examTypeQuery] }
        : examTypeQuery;
    const docs = await db
      .collection('assignments')
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    return res.json(docs);
  })
);

app.get(
  '/exams/:id',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid exam id' });
    const exam = await db.collection('assignments').findOne({
      _id,
      $or: [{ type: 'exam' }, { kind: 'exam' }],
    });
    if (!exam) return res.status(404).json({ message: 'Exam not found' });
    if (req.user.role === 'doctor') {
      const access = ensureDoctorAssignmentAccess(exam, req.user);
      if (!access.ok) return res.status(access.status).json({ message: access.message });
    }
    return res.json(exam);
  })
);

app.put(
  '/exams/:id',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid exam id' });
    const current = await db.collection('assignments').findOne({ _id });
    if (!current || !isExamAssignment(current)) return res.status(404).json({ message: 'Exam not found' });
    const access = ensureDoctorAssignmentAccess(current, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const updates = {
      title: req.body.title ?? current.title,
      description: req.body.description ?? current.description,
      totalMark: req.body.totalMark ?? current.totalMark,
      dueDate: req.body.dueDate ? new Date(req.body.dueDate) : current.dueDate,
      updatedAt: new Date(),
    };
    await db.collection('assignments').updateOne({ _id }, { $set: updates });
    await logAudit({
      actor: req.user,
      action: 'exam.update',
      targetType: 'assignment',
      targetId: idToString(_id),
      meta: { title: updates.title },
    });
    return res.json({ ...current, ...updates, examId: idToString(_id), assignmentId: idToString(_id) });
  })
);

app.delete(
  '/exams/:id',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid exam id' });
    const current = await db.collection('assignments').findOne({ _id });
    if (!current || !isExamAssignment(current)) return res.status(404).json({ message: 'Exam not found' });
    const access = ensureDoctorAssignmentAccess(current, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    await db.collection('assignments').deleteOne({ _id });
    await logAudit({
      actor: req.user,
      action: 'exam.delete',
      targetType: 'assignment',
      targetId: idToString(_id),
      meta: { title: current.title || '' },
    });
    return res.json({ deleted: true, examId: idToString(_id), assignmentId: idToString(_id) });
  })
);

app.get(
  '/assignments/my',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const query =
      req.user.role === 'admin'
        ? {}
        : doctorOwnershipFilter(req.user);
    const docs = await db.collection('assignments').find(query).sort({ createdAt: -1 }).toArray();
    return res.json(docs);
  })
);

app.get(
  '/assignments/:id',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid assignment id' });
    const doc = await db.collection('assignments').findOne({ _id });
    if (!doc) return res.status(404).json({ message: 'Assignment not found' });
    return res.json(doc);
  })
);

app.put(
  '/assignments/:id',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid assignment id' });
    const current = await db.collection('assignments').findOne({ _id });
    if (!current) return res.status(404).json({ message: 'Assignment not found' });
    if (req.user.role !== 'admin' && !isSameId(current.doctorId, req.user.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const updates = {
      title: req.body.title ?? current.title,
      description: req.body.description ?? current.description,
      totalMark: req.body.totalMark ?? current.totalMark,
      dueDate: req.body.dueDate ? new Date(req.body.dueDate) : current.dueDate,
      updatedAt: new Date(),
    };
    await db.collection('assignments').updateOne({ _id }, { $set: updates });
    return res.json({ ...current, ...updates });
  })
);

app.delete(
  '/assignments/:id',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid assignment id' });
    const current = await db.collection('assignments').findOne({ _id });
    if (!current) return res.status(404).json({ message: 'Assignment not found' });
    if (req.user.role !== 'admin' && !isSameId(current.doctorId, req.user.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    await db.collection('assignments').deleteOne({ _id });
    return res.json({ deleted: true });
  })
);

const uploadModelAnswerHandler = asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid assignment id' });
    const current = await db.collection('assignments').findOne({ _id });
    if (!current) return res.status(404).json({ message: 'Assignment not found' });
    const access = ensureDoctorAssignmentAccess(current, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    if (!uploadedFiles.length) {
      return res.json({
        ok: true,
        skipped: true,
        message: 'Model answer is optional, so upload was skipped because no file was provided.',
      });
    }
    const validType = validateUploadFiles(uploadedFiles);
    if (!validType.ok) return res.status(400).json({ message: validType.message });

    await db.collection('assignments').updateOne(
      { _id },
      {
        $set: {
          modelAnswer: {
            ...fileMetadata(uploaded),
            uploadedAt: new Date(),
          },
          modelAnswerFiles: uploadedFiles.map((file) => ({
            ...fileMetadata(file),
            uploadedAt: new Date(),
          })),
          updatedAt: new Date(),
        },
      }
    );

    return res.json({
      ok: true,
      file: uploaded.originalname,
      files: uploadedFiles.map(fileMetadata),
      count: uploadedFiles.length,
    });
  });

app.post(
  '/assignments/:id/upload',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id });
    if (!assignment) return res.status(404).json({ message: 'Assignment not found' });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    const validType = validateUploadFiles(uploadedFiles);
    if (!validType.ok) return res.status(400).json({ message: validType.message });
      let vlmExam = null;
      if (vlmApiUrl && uploadedFiles.length) {
        try {
          vlmExam = await callVlmProcessExam(uploadedFiles);
        } catch (err) {
          vlmExam = { error: err.message };
        }
      }
      const vlmError = buildVlmQuestionExtractionError(vlmExam);
      if (vlmError) {
        await db.collection('assignments').updateOne(
          { _id },
          {
            $set: {
              examFile: {
                ...fileMetadata(uploaded),
                uploadedAt: new Date(),
              },
              examFiles: uploadedFiles.map((file) => ({
                ...fileMetadata(file),
                uploadedAt: new Date(),
              })),
                vlmExamError: vlmError.message,
                vlmExamRaw: vlmError.details || vlmExam || null,
                extractionStatus: 'failed',
                questionsSource: 'vlm',
                updatedAt: new Date(),
              },
          }
        );
        return res.status(vlmError.status).json({
          ok: false,
          code: 'VLM_QUESTIONS_NOT_EXTRACTED',
          message: vlmError.message,
          details: vlmError.details || null,
        });
      }

      await db.collection('assignments').updateOne(
        { _id },
      {
        $set: {
          examFile: {
            ...fileMetadata(uploaded),
            uploadedAt: new Date(),
          },
          examFiles: uploadedFiles.map((file) => ({
            ...fileMetadata(file),
            uploadedAt: new Date(),
          })),
          ...(vlmExam && !vlmExam.error && Array.isArray(vlmExam.questions) && vlmExam.questions.length
            ? {
                questions: vlmExam.questions,
                vlmExam,
                extractionStatus: 'extracted',
                questionsSource: 'vlm',
                questionsExtractedAt: new Date(),
              }
            : vlmExam?.error
              ? { vlmExamError: vlmExam.error, extractionStatus: 'failed' }
              : {}),
          updatedAt: new Date(),
        },
      }
    );

    return res.json({
      ok: true,
      assignment_id: idToString(_id),
      file_url: null,
      file: {
        ...fileMetadata(uploaded),
      },
      files: uploadedFiles.map(fileMetadata),
        count: uploadedFiles.length,
        questionsCount: Array.isArray(vlmExam?.questions) ? vlmExam.questions.length : 0,
        vlmExam,
      });
    })
);

app.post(
  '/exams/:id/upload',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid exam id' });
    const assignment = await db.collection('assignments').findOne({ _id });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    const validType = validateUploadFiles(uploadedFiles);
    if (!validType.ok) return res.status(400).json({ message: validType.message });
      let vlmExam = null;
      if (vlmApiUrl && uploadedFiles.length) {
        try {
          vlmExam = await callVlmProcessExam(uploadedFiles);
        } catch (err) {
          vlmExam = { error: err.message };
        }
      }
      const vlmError = buildVlmQuestionExtractionError(vlmExam);
      if (vlmError) {
        await db.collection('assignments').updateOne(
          { _id },
          {
            $set: {
              examFile: {
                ...fileMetadata(uploaded),
                uploadedAt: new Date(),
              },
              examFiles: uploadedFiles.map((file) => ({
                ...fileMetadata(file),
                uploadedAt: new Date(),
              })),
                vlmExamError: vlmError.message,
                vlmExamRaw: vlmError.details || vlmExam || null,
                extractionStatus: 'failed',
                questionsSource: 'vlm',
                updatedAt: new Date(),
              },
          }
        );
        return res.status(vlmError.status).json({
          ok: false,
          code: 'VLM_QUESTIONS_NOT_EXTRACTED',
          message: vlmError.message,
          details: vlmError.details || null,
        });
      }

      await db.collection('assignments').updateOne(
        { _id },
      {
        $set: {
          examFile: {
            ...fileMetadata(uploaded),
            uploadedAt: new Date(),
          },
          examFiles: uploadedFiles.map((file) => ({
            ...fileMetadata(file),
            uploadedAt: new Date(),
          })),
          ...(vlmExam && !vlmExam.error && Array.isArray(vlmExam.questions) && vlmExam.questions.length
            ? {
                questions: vlmExam.questions,
                vlmExam,
                extractionStatus: 'extracted',
                questionsSource: 'vlm',
                questionsExtractedAt: new Date(),
              }
            : vlmExam?.error
              ? { vlmExamError: vlmExam.error, extractionStatus: 'failed' }
              : {}),
          updatedAt: new Date(),
        },
      }
    );

    return res.json({
      ok: true,
      examId: idToString(_id),
      assignmentId: idToString(_id),
      file_url: null,
      file: {
        ...fileMetadata(uploaded),
      },
        files: uploadedFiles.map(fileMetadata),
        count: uploadedFiles.length,
        questionsCount: Array.isArray(vlmExam?.questions) ? vlmExam.questions.length : 0,
        vlmExam,
      });
  })
);

app.post(
  '/assignments/:id/model-answer',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  uploadModelAnswerHandler
);
app.post(
  '/api/assignments/:id/model-answer',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  uploadModelAnswerHandler
);

app.get(
  '/assignments/:id/submissions',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const assignmentId = parseObjectId(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    const query = { assignmentId: { $in: [assignmentId, String(assignmentId)] } };
    const [docs, total] = await Promise.all([
      db.collection('submissions').find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('submissions').countDocuments(query),
    ]);
    return res.json(buildPaginatedResponse({ items: docs, total, page, limit }));
  })
);

app.post(
  '/submissions',
  auth,
  allowRoles('student'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.body.assignmentId);
    if (!assignmentId) {
      return res.status(400).json({
        message: "Invalid or missing 'assignmentId'. Send a valid Mongo ObjectId in form-data.",
      });
    }
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    if (!assignment) return res.status(404).json({ message: 'Assignment not found' });
    if (new Date(assignment.dueDate) < new Date()) {
      return res.status(400).json({ message: 'Deadline has passed' });
    }
    const hasAssignmentQuestions = Array.isArray(assignment.questions) && assignment.questions.length > 0;

    const now = new Date();
    const studentObjectId = parseObjectId(req.user.id);
    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    if (uploadedFiles.length) {
      const validType = validateUploadFiles(uploadedFiles);
      if (!validType.ok) return res.status(400).json({ message: validType.message });
    }
    const existingSubmission = await db.collection('submissions').findOne({
      assignmentId,
      studentId: { $in: userIdAlternatives(req.user.id) },
      status: { $ne: 'graded' },
    });
    if (existingSubmission) {
      const updateFields = {
        answerText: req.body.answerText || existingSubmission.answerText || '',
        course: getCourseIdForPipeline(assignment),
        assignmentCourse: getCourseIdForPipeline(assignment),
        studentName: pickDisplayName(req.user.name, req.user.email),
        studentEmail: req.user.email,
        status: 'submitted',
        updatedAt: now,
      };
      if (uploaded) {
        updateFields.file = {
          ...fileMetadata(uploaded),
        };
        updateFields.files = uploadedFiles.map(fileMetadata);
      }
      await db.collection('submissions').updateOne({ _id: existingSubmission._id }, { $set: updateFields });
      const updated = await db.collection('submissions').findOne({ _id: existingSubmission._id });
      setImmediate(() => {
        runSubmissionPipeline({ submissionId: idToString(existingSubmission._id), uploadedFiles }).catch((err) => {
          console.error(
            `[pipeline] submission_id=${idToString(existingSubmission._id)} error=${err.message || 'unknown error'}`
          );
        });
      });
      return res.json({
        ...updated,
        gradingReady: hasAssignmentQuestions,
        warning: hasAssignmentQuestions
          ? null
          : 'Assignment/exam questions are missing. Ask the doctor to upload the assignment/exam paper before AI grading.',
      });
    }
    const doc = {
      assignmentId,
      assignmentTitle: assignment.title,
      course: getCourseIdForPipeline(assignment),
      assignmentCourse: getCourseIdForPipeline(assignment),
      studentId: studentObjectId || req.user.id,
      studentName: pickDisplayName(req.user.name, req.user.email),
      studentEmail: req.user.email,
      answerText: req.body.answerText || '',
      status: 'submitted',
      score: null,
      file: uploaded
        ? {
            ...fileMetadata(uploaded),
          }
        : null,
      files: uploadedFiles.map(fileMetadata),
      gradingReady: hasAssignmentQuestions,
      createdAt: now,
      updatedAt: now,
    };

    const result = await db.collection('submissions').insertOne(doc);
    doc._id = result.insertedId;

    setImmediate(() => {
      runSubmissionPipeline({ submissionId: idToString(doc._id), uploadedFiles }).catch((err) => {
        console.error(
          `[pipeline] submission_id=${idToString(doc._id)} error=${err.message || 'unknown error'}`
        );
      });
    });

    return res.status(201).json({
      ...doc,
      warning: hasAssignmentQuestions
        ? null
        : 'Assignment/exam questions are missing. Ask the doctor to upload the assignment/exam paper before AI grading.',
    });
  })
);

app.get(
  '/submissions/my',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    if (req.user.role === 'student') {
      const query = { studentId: { $in: userIdAlternatives(req.user.id) } };
      const [docs, total] = await Promise.all([
        db.collection('submissions').find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        db.collection('submissions').countDocuments(query),
      ]);
      return res.json(buildPaginatedResponse({ items: docs, total, page, limit }));
    }

    if (req.user.role === 'doctor') {
      const assignments = await db
        .collection('assignments')
        .find(doctorOwnershipFilter(req.user), { projection: { _id: 1 } })
        .toArray();
      const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
      const query = assignmentIds.length ? { assignmentId: { $in: assignmentIds } } : null;
      if (!query) {
        return res.json(buildPaginatedResponse({ items: [], total: 0, page, limit }));
      }
      const [docs, total] = await Promise.all([
        db.collection('submissions').find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
        db.collection('submissions').countDocuments(query),
      ]);
      return res.json(buildPaginatedResponse({ items: docs, total, page, limit }));
    }

    const query = {};
    const [docs, total] = await Promise.all([
      db.collection('submissions').find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('submissions').countDocuments(query),
    ]);
    return res.json(buildPaginatedResponse({ items: docs, total, page, limit }));
  })
);

app.get(
  '/submissions/:id',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid submission id' });
    const doc = await db.collection('submissions').findOne({ _id });
    if (!doc) return res.status(404).json({ message: 'Submission not found' });
    if (req.user.role === 'student' && !isSameId(doc.studentId, req.user.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (req.user.role === 'doctor') {
      const assignmentId = getSubmissionAssignmentObjectId(doc);
      if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id on submission' });
      const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
      const access = ensureDoctorAssignmentAccess(assignment, req.user);
      if (!access.ok) return res.status(access.status).json({ message: access.message });
    }
    return res.json(doc);
  })
);

app.post(
  '/submissions/:id/reprocess',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid submission id' });

    const submission = await db.collection('submissions').findOne({ _id });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    const assignmentId = getSubmissionAssignmentObjectId(submission);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id on submission' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const uploadedFiles = pickUploadedFiles(req.files);
    if (uploadedFiles.length) {
      const validType = validateUploadFiles(uploadedFiles);
      if (!validType.ok) return res.status(400).json({ message: validType.message });
    }

    const hasQuestions = Array.isArray(assignment?.questions) && assignment.questions.length > 0;
    if (!hasQuestions) {
      return res.status(400).json({
        message:
          'Assignment/exam questions are missing. Upload the assignment/exam paper first, then reprocess the submission.',
        code: 'ASSIGNMENT_QUESTIONS_REQUIRED',
      });
    }

    const hasExistingAnswer =
      Boolean(String(submission.answerText || '').trim()) ||
      (Array.isArray(submission.answers) && submission.answers.length > 0);
    if (!uploadedFiles.length && !hasExistingAnswer) {
      return res.status(400).json({
        message:
          "Student answer images are required for reprocessing because this submission does not have extracted answers. Send form-data field 'images' or 'file'.",
        code: 'SUBMISSION_ANSWERS_REQUIRED',
      });
    }

    await db.collection('submissions').updateOne(
      { _id },
      {
        $set: {
          status: 'submitted',
          score: null,
          similarity: null,
          scoreBreakdown: [],
          feedback: '',
          pipelineStatus: 'queued',
          pipelineError: null,
          pipelineUpdatedAt: new Date(),
          ...(uploadedFiles.length
            ? {
                file: fileMetadata(uploadedFiles[0]),
                files: uploadedFiles.map(fileMetadata),
              }
            : {}),
        },
      }
    );

    setImmediate(() => {
      runSubmissionPipeline({ submissionId: idToString(_id), uploadedFiles }).catch((err) => {
        console.error(`[pipeline] reprocess submission_id=${idToString(_id)} error=${err.message || 'unknown error'}`);
      });
    });

    return res.json({
      message: 'Submission reprocess started',
      submissionId: idToString(_id),
      assignmentId: idToString(assignmentId),
      course: getCourseIdForPipeline(assignment),
      uploadedFiles: uploadedFiles.length,
      status: 'queued',
    });
  })
);

app.put(
  [
    '/submissions/:id/grade',
    '/submissions/:submissionId/grade',
    '/api/submissions/:id/grade',
    '/api/submissions/:submissionId/grade',
  ],
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id || req.params.submissionId);
    if (!_id) return res.status(400).json({ message: 'Invalid submission id' });
    const score = Number(req.body.score);
    if (Number.isNaN(score)) return res.status(400).json({ message: 'score is required' });
    const existing = await db.collection('submissions').findOne({ _id });
    if (!existing) return res.status(404).json({ message: 'Submission not found' });

    if (req.user.role === 'doctor') {
      const assignmentObjId = getSubmissionAssignmentObjectId(existing);
      if (!assignmentObjId) return res.status(400).json({ message: 'Invalid assignment id on submission' });
      const assignment = await db.collection('assignments').findOne({ _id: assignmentObjId });
      const access = ensureDoctorAssignmentAccess(assignment, req.user);
      if (!access.ok) return res.status(access.status).json({ message: access.message });
    }

    const result = await db.collection('submissions').findOneAndUpdate(
      { _id },
      { $set: { score, status: 'graded', updatedAt: new Date() } },
      { returnDocument: 'after' }
    );
    const updated = unwrapFindOneAndUpdateResult(result);
    if (!updated) return res.status(404).json({ message: 'Submission not found' });
    await logAudit({
      actor: req.user,
      action: 'submission.grade.override',
      targetType: 'submission',
      targetId: idToString(updated._id),
      meta: { score },
    });
    return res.json(updated);
  })
);

app.get(
  '/results/my',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const docs = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) }, status: 'graded' })
      .sort({ updatedAt: -1 })
      .toArray();
    return res.json(docs);
  })
);

app.get(
  '/results/assignment/:assignmentId',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    const docs = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .toArray();
    return res.json(docs);
  })
);

app.get(
  '/analytics/doctor',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentsQuery =
      req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user);
    const assignmentDocs = await db.collection('assignments').find(assignmentsQuery).toArray();
    const assignmentIds = assignmentDocs.flatMap((a) => [a._id, String(a._id)]);
    const submissionDocs = assignmentIds.length
      ? await db
          .collection('submissions')
          .find({ assignmentId: { $in: assignmentIds } })
          .toArray()
      : [];
    const graded = submissionDocs.filter((s) => typeof s.score === 'number');
    const avgScore = graded.length
      ? graded.reduce((sum, s) => sum + s.score, 0) / graded.length
      : 0;
    return res.json({
      assignmentsCount: assignmentDocs.length,
      submissionsCount: submissionDocs.length,
      gradedCount: graded.length,
      averageScore: Number(avgScore.toFixed(2)),
    });
  })
);

app.get(
  '/student/dashboard',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const now = new Date();
    const studentId = parseObjectId(req.user.id);
    const studentUser = studentId ? await db.collection('users').findOne({ _id: studentId }) : null;
    const studentCourses = Array.isArray(studentUser?.courses)
      ? studentUser.courses.map((c) => String(c).trim()).filter(Boolean)
      : [];
    const assignments = await db
      .collection('assignments')
      .find(studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } })
      .sort({ dueDate: 1 })
      .toArray();
    const submissions = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) } })
      .toArray();
    const byAssignment = new Map(submissions.map((s) => [idToString(s.assignmentId), s]));

    const pendingAssignments = assignments.filter((a) => !byAssignment.has(idToString(a._id))).length;
    const upcomingExams = assignments.filter((a) => new Date(a.dueDate) > now).length;
    const tasks = assignments.slice(0, 10).map((a) => {
      const sub = byAssignment.get(idToString(a._id));
      return {
        assignmentId: idToString(a._id),
        title: a.title || 'Untitled assignment',
        dueDate: a.dueDate,
        status: mapStudentAssignmentStatus(sub),
        action: sub ? 'view_submission' : 'submit_answer',
      };
    });

    return res.json({
      summary: { pendingAssignments, upcomingExams },
      tasks,
    });
  })
);
app.get('/api/student/dashboard', auth, allowRoles('student'), asyncRoute(async (req, res) => {
  const db = getDbOrFail();
  const now = new Date();
  const studentId = parseObjectId(req.user.id);
  const studentUser = studentId ? await db.collection('users').findOne({ _id: studentId }) : null;
  const studentCourses = Array.isArray(studentUser?.courses)
    ? studentUser.courses.map((c) => String(c).trim()).filter(Boolean)
    : [];
  const assignments = await db
    .collection('assignments')
    .find(studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } })
    .sort({ dueDate: 1 })
    .toArray();
  const submissions = await db
    .collection('submissions')
    .find({ studentId: { $in: userIdAlternatives(req.user.id) } })
    .toArray();
  const byAssignment = new Map(submissions.map((s) => [idToString(s.assignmentId), s]));
  const pendingAssignments = assignments.filter((a) => !byAssignment.has(idToString(a._id))).length;
  const upcomingExams = assignments.filter((a) => new Date(a.dueDate) > now).length;
  const tasks = assignments.slice(0, 10).map((a) => {
    const sub = byAssignment.get(idToString(a._id));
    return {
      assignmentId: idToString(a._id),
      title: a.title || 'Untitled assignment',
      dueDate: a.dueDate,
      status: mapStudentAssignmentStatus(sub),
      action: sub ? 'view_submission' : 'submit_answer',
    };
  });
  return res.json({ summary: { pendingAssignments, upcomingExams }, tasks });
}));

app.get(
  '/student/assignments',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const studentId = parseObjectId(req.user.id);
    const studentUser = studentId ? await db.collection('users').findOne({ _id: studentId }) : null;
    const studentCourses = Array.isArray(studentUser?.courses)
      ? studentUser.courses.map((c) => String(c).trim()).filter(Boolean)
      : [];
      const assignments = await db
        .collection('assignments')
        .find(andFilters(
          assignmentOnlyFilter,
          studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } }
        ))
      .sort({ createdAt: -1 })
      .toArray();
    const submissions = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) } })
      .toArray();
    const byAssignment = new Map(submissions.map((s) => [idToString(s.assignmentId), s]));

    const items = assignments.map((a) => {
      const sub = byAssignment.get(idToString(a._id));
      const published = isPublishedForStudents(a);
      const rawStatus = mapStudentAssignmentStatus(sub);
      const status = published || rawStatus === 'not_submitted' ? rawStatus : 'submitted';
      const score = published ? getSubmissionScore(sub) : null;
      const similarity = published ? getSubmissionSimilarity(sub) : null;
      const percentage = published ? getSubmissionPercentage(sub, a) : null;
      const resultStatus = published ? getSubmissionResultStatus(sub, a) : null;
      return {
        assignmentId: idToString(a._id),
        type: 'assignment',
        kind: 'assignment',
        title: a.title || 'Untitled assignment',
        dueDate: a.dueDate,
        totalMark: a.totalMark ?? null,
        passingPercentage: 50,
        resultsPublished: published,
        status,
        score,
        percentage,
        resultStatus,
        similarity,
        action: status === 'not_submitted' ? 'submit_answer' : published ? 'view_submission' : 'await_results',
      };
    });

    return res.json({ items });
  })
);
app.get('/api/student/assignments', auth, allowRoles('student'), asyncRoute(async (req, res) => {
  const db = getDbOrFail();
  const studentId = parseObjectId(req.user.id);
  const studentUser = studentId ? await db.collection('users').findOne({ _id: studentId }) : null;
  const studentCourses = Array.isArray(studentUser?.courses)
    ? studentUser.courses.map((c) => String(c).trim()).filter(Boolean)
    : [];
    const assignments = await db
      .collection('assignments')
      .find(andFilters(
        assignmentOnlyFilter,
        studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } }
      ))
    .sort({ createdAt: -1 })
    .toArray();
  const submissions = await db
    .collection('submissions')
    .find({ studentId: { $in: userIdAlternatives(req.user.id) } })
    .toArray();
  const byAssignment = new Map(submissions.map((s) => [idToString(s.assignmentId), s]));
  const items = assignments.map((a) => {
    const sub = byAssignment.get(idToString(a._id));
    const published = isPublishedForStudents(a);
    const rawStatus = mapStudentAssignmentStatus(sub);
    const status = published || rawStatus === 'not_submitted' ? rawStatus : 'submitted';
    const score = published ? getSubmissionScore(sub) : null;
    const similarity = published ? getSubmissionSimilarity(sub) : null;
    const percentage = published ? getSubmissionPercentage(sub, a) : null;
    const resultStatus = published ? getSubmissionResultStatus(sub, a) : null;
    return {
      assignmentId: idToString(a._id),
      type: 'assignment',
      kind: 'assignment',
      title: a.title || 'Untitled assignment',
      dueDate: a.dueDate,
      totalMark: a.totalMark ?? null,
      passingPercentage: 50,
      resultsPublished: published,
      status,
      score,
      percentage,
      resultStatus,
      similarity,
      action: status === 'not_submitted' ? 'submit_answer' : published ? 'view_submission' : 'await_results',
    };
  });
  return res.json({ items });
}));

app.get(
  '/student/exams',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const studentId = parseObjectId(req.user.id);
    const studentUser = studentId ? await db.collection('users').findOne({ _id: studentId }) : null;
    const studentCourses = Array.isArray(studentUser?.courses)
      ? studentUser.courses.map((c) => String(c).trim()).filter(Boolean)
      : [];
      const assignments = await db
        .collection('assignments')
        .find(andFilters(
          examOnlyFilter,
          studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } }
        ))
      .sort({ dueDate: 1 })
      .skip(skip)
      .limit(limit)
      .toArray();
      const total = await db.collection('assignments').countDocuments(andFilters(
        examOnlyFilter,
        studentCourses.length ? { course: { $in: studentCourses } } : { _id: { $exists: false } }
      ));
    const submissions = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) } })
      .toArray();
    const byAssignment = new Map(submissions.map((s) => [idToString(s.assignmentId), s]));

    const items = assignments.map((a) => {
      const sub = byAssignment.get(idToString(a._id));
      const published = isPublishedForStudents(a);
      const rawStatus = mapStudentExamStatus(sub);
      const status = published || rawStatus === 'not_started' ? rawStatus : 'submitted';
      const score = published ? getSubmissionScore(sub) : null;
      const similarity = published ? getSubmissionSimilarity(sub) : null;
      const percentage = published ? getSubmissionPercentage(sub, a) : null;
      const resultStatus = published ? getSubmissionResultStatus(sub, a) : null;
      const action =
        status === 'not_started'
          ? 'start_exam'
          : published
            ? 'view_result'
            : 'await_results';
      return {
        examId: idToString(a._id),
        assignmentId: idToString(a._id),
        type: 'exam',
        kind: 'exam',
        title: a.title || 'Untitled exam',
        dueDate: a.dueDate,
        totalMark: a.totalMark ?? null,
        passingPercentage: 50,
        resultsPublished: published,
        status,
        score,
        percentage,
        resultStatus,
        similarity,
        action,
      };
    });

    return res.json(buildPaginatedResponse({ items, total, page, limit }));
  })
);

app.get(
  '/student/results/summary',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const submissionsRaw = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) }, status: 'graded' })
      .sort({ updatedAt: -1 })
      .toArray();
    const assignmentIds = submissionsRaw
      .map((s) => getSubmissionAssignmentObjectId(s))
      .filter(Boolean);
    const assignments = assignmentIds.length
      ? await db.collection('assignments').find({ _id: { $in: assignmentIds } }).toArray()
      : [];
    const byAssignmentId = new Map(assignments.map((a) => [idToString(a._id), a]));
    const submissions = submissionsRaw.filter((s) => {
      const assignment = byAssignmentId.get(idToString(getSubmissionAssignmentObjectId(s)));
      return isPublishedForStudents(assignment);
    });

    const total = submissions.length;
    const passed = submissions.filter((s) => {
      const assignment = byAssignmentId.get(idToString(getSubmissionAssignmentObjectId(s)));
      return getSubmissionResultStatus(s, assignment) === 'passed';
    }).length;
    const failed = total - passed;
    const items = submissions.map((s) => {
      const assignment = byAssignmentId.get(idToString(getSubmissionAssignmentObjectId(s)));
      const score = getSubmissionScore(s);
      return {
        submissionId: idToString(s._id),
        assignmentId: idToString(s.assignmentId),
        type: getAssignmentType(assignment),
        kind: getAssignmentType(assignment),
        title: s.assignmentTitle || assignment?.title || 'Untitled',
        score,
        totalMark: getAssignmentTotalMark(assignment, 100),
        percentage: getSubmissionPercentage(s, assignment),
        status: getSubmissionResultStatus(s, assignment),
      };
    });

    return res.json({
      summary: { total, passed, failed },
      items,
    });
  })
);

app.get(
  '/student/results/:submissionId/details',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const submissionId = parseObjectId(req.params.submissionId);
    if (!submissionId) return res.status(400).json({ message: 'Invalid submission id' });

    const submission = await db.collection('submissions').findOne({ _id: submissionId });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });
    if (!isSameId(submission.studentId, req.user.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const assignmentId = submission.assignmentId instanceof ObjectId
      ? submission.assignmentId
      : parseObjectId(submission.assignmentId);
    const assignment = assignmentId ? await db.collection('assignments').findOne({ _id: assignmentId }) : null;
    if (!isPublishedForStudents(assignment)) {
      return res.status(403).json({ message: 'Result not published yet' });
    }
    const totalMark = Number(assignment?.totalMark ?? 100);
    const score = getSubmissionScore(submission) ?? 0;
    const percent = totalMark > 0 ? (score / totalMark) * 100 : 0;
    const similarity = getSubmissionSimilarity(submission);

    const scoreBreakdown = Array.isArray(submission.scoreBreakdown) && submission.scoreBreakdown.length
      ? submission.scoreBreakdown.map(sanitizeGradeResultForReview)
      : [
          {
            question: 'Overall',
            score,
            outOf: totalMark,
          },
        ];

    return res.json({
      submissionId: idToString(submission._id),
      assignmentId: idToString(submission.assignmentId),
      type: getAssignmentType(assignment),
      kind: getAssignmentType(assignment),
      title: submission.assignmentTitle || assignment?.title || 'Untitled',
      course: submission.course || getCourseIdForPipeline(assignment),
      score,
      totalMark,
      percentage: Number(percent.toFixed(2)),
      similarity,
      status: percent >= 50 ? 'passed' : 'failed',
      scoreBreakdown,
      grade_results: scoreBreakdown,
      items: buildQuestionReviewItems({ assignment, submission }),
    });
  })
);

app.get(
  '/student/submissions/:submissionId/review',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const submissionId = parseObjectId(req.params.submissionId);
    if (!submissionId) return res.status(400).json({ message: 'Invalid submission id' });

    const submission = await db.collection('submissions').findOne({ _id: submissionId });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });
    if (!isSameId(submission.studentId, req.user.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    const assignmentId = submission.assignmentId instanceof ObjectId
      ? submission.assignmentId
      : parseObjectId(submission.assignmentId);
    const assignment = assignmentId ? await db.collection('assignments').findOne({ _id: assignmentId }) : null;
    if (!isPublishedForStudents(assignment)) {
      return res.status(403).json({ message: 'Result not published yet' });
    }

    const reviewItems = buildQuestionReviewItems({ assignment, submission });
    const score = getSubmissionScore(submission);

    return res.json({
      submissionId: idToString(submission._id),
      assignmentId: idToString(submission.assignmentId),
      type: getAssignmentType(assignment),
      kind: getAssignmentType(assignment),
      title: submission.assignmentTitle || assignment?.title || 'Untitled',
      course: submission.course || getCourseIdForPipeline(assignment),
      score,
      totalMark: getAssignmentTotalMark(assignment, 100),
      percentage: getSubmissionPercentage(submission, assignment),
      status: getSubmissionResultStatus(submission, assignment),
      similarity: getSubmissionSimilarity(submission),
      grade_results: Array.isArray(submission.scoreBreakdown)
        ? submission.scoreBreakdown.map(sanitizeGradeResultForReview)
        : [],
      items: reviewItems,
    });
  })
);

app.post(
  '/student/exams/:assignmentId/offline-submit',
  auth,
  allowRoles('student'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    if (!assignment) return res.status(404).json({ message: 'Assignment not found' });

    const files = (req.files || []).filter((f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname));
    if (files.length === 0) {
      return res.status(400).json({
        message: "Missing images. Send multipart/form-data with one or more files in 'images' (or 'image' / 'file').",
      });
    }

    const now = new Date();
    const studentObjectId = parseObjectId(req.user.id);
    const submissionDoc = {
      assignmentId,
      assignmentTitle: assignment.title,
      studentId: studentObjectId || req.user.id,
      studentName: pickDisplayName(req.user.name, req.user.email),
      studentEmail: req.user.email,
      answerText: String(req.body.answerText || '').trim(),
      status: 'submitted',
      score: null,
      files: files.map((f) => ({
        originalName: f.originalname,
        mimeType: f.mimetype,
        size: f.size,
      })),
      createdAt: now,
      updatedAt: now,
    };

    const result = await db.collection('submissions').insertOne(submissionDoc);
    submissionDoc._id = result.insertedId;

    return res.status(201).json({
      ok: true,
      submissionId: idToString(submissionDoc._id),
      filesCount: files.length,
      status: submissionDoc.status,
    });
  })
);

app.get(
  '/student/profile',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const userId = parseObjectId(req.user.id);
    const user = userId ? await db.collection('users').findOne({ _id: userId }) : null;
    const submissions = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) }, status: 'graded' })
      .toArray();

    const examsTaken = submissions.length;
    const passed = submissions.filter((s) => typeof s.score === 'number' && s.score >= 50).length;
    const failed = examsTaken - passed;

    return res.json({
      user: {
        id: req.user.id,
        name: user?.name || req.user.name || '',
        email: user?.email || req.user.email || '',
        role: user?.role || req.user.role || 'student',
        phone: user?.phone || '',
      },
      stats: {
        examsTaken,
        passed,
        failed,
      },
      courses: Array.isArray(user?.courses) ? user.courses : [],
    });
  })
);

app.get(
  '/doctor/dashboard',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
      const ownershipQuery = req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user);
      const assignments = await db.collection('assignments').find(ownershipQuery).sort({ dueDate: 1 }).toArray();

    const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
    const submissions = assignmentIds.length
      ? await db.collection('submissions').find({ assignmentId: { $in: assignmentIds } }).toArray()
      : [];
    const pendingGrading = submissions.filter((s) => s.status !== 'graded').length;
      const examAssignments = assignments.filter(isExamAssignment);
      const activeExams = examAssignments.filter((a) => new Date(a.dueDate) >= new Date()).length;

      const recentExams = examAssignments.slice(0, 10).map((a) => {
      const related = submissions.filter((s) => isSameId(s.assignmentId, a._id));
      const attemptedCount = related.length;
      const gradedCount = related.filter((s) => s.status === 'graded').length;
      const pendingCount = attemptedCount - gradedCount;
      const gradingStatus = pendingCount > 0 ? 'grading' : attemptedCount > 0 ? 'graded' : 'pending';
      return {
        assignmentId: idToString(a._id),
        title: a.title || 'Untitled exam',
        type: getAssignmentType(a),
        status: getAssignmentStatus(a),
        dueDate: a.dueDate,
        totalMark: a.totalMark ?? null,
        attemptedCount,
        submissions: {
          graded: gradedCount,
          pending: pendingCount,
        },
        gradingStatus,
        action: pendingCount > 0 ? 'grade_exam' : 'view_results',
      };
    });

    return res.json({
      summary: {
        pendingGrading,
        activeExams,
      },
      recentExams,
    });
  })
);

app.get(
  '/doctor/assignments',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
      const assignmentsQuery = andFilters(
        req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user),
        assignmentOnlyFilter
      );
      const assignments = await db.collection('assignments').find(assignmentsQuery).sort({ createdAt: -1 }).toArray();

    const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
    const submissions = assignmentIds.length
      ? await db.collection('submissions').find({ assignmentId: { $in: assignmentIds } }).toArray()
      : [];

    const items = assignments.map((a) => {
      const related = submissions.filter((s) => isSameId(s.assignmentId, a._id));
      const attemptedCount = related.length;
      const gradedCount = related.filter((s) => s.status === 'graded').length;
      return {
        assignmentId: idToString(a._id),
        title: a.title || 'Untitled assignment',
          type: 'assignment',
          kind: 'assignment',
        status: getAssignmentStatus(a),
        dueDate: a.dueDate,
        totalMark: a.totalMark ?? null,
        attemptedCount,
        submissions: {
          graded: gradedCount,
          pending: attemptedCount - gradedCount,
        },
        action: 'view_submissions',
      };
    });

    return res.json({ items });
  })
);

app.get(
  '/doctor/assignments/:assignmentId/submissions',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .sort({ createdAt: -1 })
      .toArray();

    const attemptedCount = submissions.length;
    const gradedCount = submissions.filter((s) => s.status === 'graded').length;
    const pendingCount = attemptedCount - gradedCount;

    const items = await Promise.all(
      submissions.map(async (s) => {
        const student = await getStudentIdentityForSubmission(db, s);
        return {
          submissionId: idToString(s._id),
          studentId: student.id,
          studentName: student.name,
          studentEmail: student.email,
          status: s.status === 'graded' ? 'ai_graded' : s.status === 'submitted' ? 'submitted' : s.status,
          score: getSubmissionScore(s),
          similarity: getSubmissionSimilarity(s),
          action: 'review_submission',
        };
      })
    );

    return res.json({
	      assignmentId: idToString(assignmentId),
	      title: assignment?.title || 'Untitled assignment',
	      type: 'assignment',
	      kind: 'assignment',
	      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark: assignment?.totalMark ?? null,
      attemptedCount,
      submissions: {
        graded: gradedCount,
        pending: pendingCount,
      },
      items,
    });
  })
);

app.get(
  '/doctor/exams',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
      const db = getDbOrFail();
      const { page, limit, skip } = parsePagination(req.query);
      const ownershipQuery = req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user);
      const assignmentsQuery = andFilters(ownershipQuery, examOnlyFilter);
    const [assignments, total] = await Promise.all([
      db.collection('assignments').find(assignmentsQuery).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('assignments').countDocuments(assignmentsQuery),
    ]);

    const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
    const submissions = assignmentIds.length
      ? await db.collection('submissions').find({ assignmentId: { $in: assignmentIds } }).toArray()
      : [];

    const items = assignments.map((a) => {
      const related = submissions.filter((s) => isSameId(s.assignmentId, a._id));
      const attemptedCount = related.length;
      const gradedCount = related.filter((s) => s.status === 'graded').length;
      return {
        examId: idToString(a._id),
        assignmentId: idToString(a._id),
        title: a.title || 'Untitled exam',
          type: 'exam',
          kind: 'exam',
        status: getAssignmentStatus(a),
        dueDate: a.dueDate,
        totalMark: a.totalMark ?? null,
        attemptedCount,
        submissions: {
          graded: gradedCount,
          pending: attemptedCount - gradedCount,
        },
        action: 'view_submissions',
      };
    });

    return res.json(buildPaginatedResponse({ items, total, page, limit }));
  })
);

app.put(
  '/student/profile',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { value, error } = studentProfileUpdateSchema.validate(req.body, {
      allowUnknown: false,
      stripUnknown: true,
    });
    if (error) return res.status(400).json({ message: error.message });

    const userId = parseObjectId(req.user.id);
    if (!userId) return res.status(400).json({ message: 'Invalid user id in token' });

    const updates = { updatedAt: new Date() };
    if (Object.prototype.hasOwnProperty.call(value, 'department')) {
      updates.department = String(value.department || '').trim();
    }
    if (Object.prototype.hasOwnProperty.call(value, 'courses')) {
      updates.courses = [...new Set((value.courses || []).map((c) => String(c).trim()).filter(Boolean))];
    }

    const result = await db.collection('users').findOneAndUpdate(
      { _id: userId },
      { $set: updates },
      { returnDocument: 'after' }
    );
    const student = unwrapFindOneAndUpdateResult(result);
    if (!student) return res.status(404).json({ message: 'Student not found' });

    await logAudit({
      actor: req.user,
      action: 'student.profile.update',
      targetType: 'user',
      targetId: idToString(student._id),
      meta: { department: student.department || '' },
    });

    return res.json({
      message: 'Profile updated',
      student: {
        id: idToString(student._id),
        name: student.name || '',
        email: student.email || '',
        role: student.role || 'student',
        department: student.department || '',
        courses: Array.isArray(student.courses) ? student.courses : [],
      },
    });
  })
);

app.get(
  '/doctor/exams/:examId/submissions',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.examId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid exam id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .sort({ createdAt: -1 })
      .toArray();

    const attemptedCount = submissions.length;
    const gradedCount = submissions.filter((s) => s.status === 'graded').length;
    const pendingCount = attemptedCount - gradedCount;

    const items = await Promise.all(
      submissions.map(async (s) => {
        const student = await getStudentIdentityForSubmission(db, s);
        return {
          submissionId: idToString(s._id),
          studentId: student.id,
          studentName: student.name,
          studentEmail: student.email,
          status: s.status === 'graded' ? 'ai_graded' : s.status === 'submitted' ? 'submitted' : s.status,
          score: getSubmissionScore(s),
          similarity: getSubmissionSimilarity(s),
          action: 'review_submission',
        };
      })
    );

    return res.json({
      examId: idToString(assignmentId),
      assignmentId: idToString(assignmentId),
      title: assignment?.title || 'Untitled exam',
      type: getAssignmentType(assignment),
      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark: assignment?.totalMark ?? null,
      attemptedCount,
      submissions: {
        graded: gradedCount,
        pending: pendingCount,
      },
      items,
    });
  })
);

app.get(
  '/doctor/submissions/:submissionId/review',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const submissionId = parseObjectId(req.params.submissionId);
    if (!submissionId) return res.status(400).json({ message: 'Invalid submission id' });

    const submission = await db.collection('submissions').findOne({ _id: submissionId });
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    const assignmentId = submission.assignmentId instanceof ObjectId
      ? submission.assignmentId
      : parseObjectId(submission.assignmentId);
    const assignment = assignmentId ? await db.collection('assignments').findOne({ _id: assignmentId }) : null;
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const items = buildQuestionReviewItems({ assignment, submission });
    const student = await getStudentIdentityForSubmission(db, submission);

    return res.json({
      submissionId: idToString(submission._id),
      assignmentId: idToString(submission.assignmentId),
      assignmentTitle: submission.assignmentTitle || assignment?.title || 'Untitled',
      course: submission.course || getCourseIdForPipeline(assignment),
      student,
      score: getSubmissionScore(submission),
      similarity: getSubmissionSimilarity(submission),
      status: submission.status || 'submitted',
      grade_results: Array.isArray(submission.scoreBreakdown)
        ? submission.scoreBreakdown.map(sanitizeGradeResultForReview)
        : [],
      items,
    });
  })
);

app.get(
  '/doctor/results/ranking',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const assignmentsQuery =
      req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user);
    const [assignments, total] = await Promise.all([
      db.collection('assignments').find(assignmentsQuery).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('assignments').countDocuments(assignmentsQuery),
    ]);
    const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
    const submissions = assignmentIds.length
      ? await db.collection('submissions').find({ assignmentId: { $in: assignmentIds } }).toArray()
      : [];

    const items = assignments.map((a) => {
      const related = submissions.filter((s) => isSameId(s.assignmentId, a._id));
      const gradedCount = related.filter((s) => s.status === 'graded').length;
      const pendingCount = related.length - gradedCount;
      return {
        assignmentId: idToString(a._id),
        title: a.title || 'Untitled',
        type: getAssignmentType(a),
        status: getAssignmentStatus(a),
        dueDate: a.dueDate || null,
        totalMark: a.totalMark ?? null,
        attemptedCount: related.length,
        submissions: {
          graded: gradedCount,
          pending: pendingCount,
        },
        action: 'view_details',
      };
    });

    return res.json(buildPaginatedResponse({ items, total, page, limit }));
  })
);

app.get(
  '/doctor/results/:assignmentId/details',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .toArray();

    const attemptedCount = submissions.length;
    const graded = submissions.filter((s) => typeof s.score === 'number');
    const gradedCount = graded.length;
    const pendingCount = attemptedCount - gradedCount;
    const totalMark = Number(assignment?.totalMark ?? 20);
    const scores = graded.map((s) => Number(s.score));
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
    const highestScore = scores.length ? Math.max(...scores) : 0;
    const lowestScore = scores.length ? Math.min(...scores) : 0;

    const similarityValues = submissions
      .map((s) => {
        if (typeof s.similarity === 'number') return s.similarity;
        if (Array.isArray(s.answers)) {
          const vals = s.answers.map((a) => a.similarity).filter((v) => typeof v === 'number');
          if (vals.length) return vals.reduce((a, b) => a + b, 0) / vals.length;
        }
        return null;
      })
      .filter((v) => v !== null);
    const avgSimilarity = similarityValues.length
      ? similarityValues.reduce((a, b) => a + b, 0) / similarityValues.length
      : 0;

    const sortBy = String(req.query.sortBy || 'score').toLowerCase();
    const rows = await Promise.all(submissions.map(async (s) => {
      const student = await getStudentIdentityForSubmission(db, s);
      const similarity =
        typeof s.similarity === 'number'
          ? s.similarity
          : Array.isArray(s.answers)
            ? (() => {
                const vals = s.answers.map((a) => a.similarity).filter((v) => typeof v === 'number');
                return vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
              })()
            : null;
      return {
        submissionId: idToString(s._id),
        studentId: student.id,
        studentName: student.name,
        score: typeof s.score === 'number' ? s.score : null,
        outOf: totalMark,
        similarity: similarity !== null ? Number(similarity.toFixed(2)) : null,
        action: 'view_submission',
      };
    }));

    if (sortBy === 'name') {
      rows.sort((a, b) => String(a.studentName).localeCompare(String(b.studentName)));
    } else if (sortBy === 'similarity') {
      rows.sort((a, b) => (b.similarity ?? -1) - (a.similarity ?? -1));
    } else {
      rows.sort((a, b) => (b.score ?? -1) - (a.score ?? -1));
    }

    return res.json({
      assignmentId: idToString(assignmentId),
      title: assignment?.title || 'Untitled',
      type: getAssignmentType(assignment),
      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark,
      attemptedCount,
      submissions: {
        graded: gradedCount,
        pending: pendingCount,
      },
      stats: {
        avgScore: Number(avgScore.toFixed(2)),
        highestScore,
        lowestScore,
        avgSimilarity: Number(avgSimilarity.toFixed(2)),
      },
      rows,
    });
  })
);

app.get(
  '/doctor/exams/:examId/results',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.examId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid exam id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .toArray();

    const attemptedCount = submissions.length;
    const graded = submissions.filter((s) => typeof s.score === 'number');
    const gradedCount = graded.length;
    const pendingCount = attemptedCount - gradedCount;
    const totalMark = Number(assignment?.totalMark ?? 20);

    return res.json({
      examId: idToString(assignmentId),
      assignmentId: idToString(assignmentId),
      title: assignment?.title || 'Untitled',
      type: getAssignmentType(assignment),
      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark,
      attemptedCount,
      submissions: {
        graded: gradedCount,
        pending: pendingCount,
      },
    });
  })
);

app.post(
  '/doctor/results/:assignmentId/publish',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    await db.collection('assignments').updateOne(
      { _id: assignmentId },
      { $set: { resultsPublished: true, resultsPublishedAt: new Date(), updatedAt: new Date() } }
    );

    await logAudit({
      actor: req.user,
      action: 'results.publish',
      targetType: 'assignment',
      targetId: idToString(assignmentId),
      meta: { route: '/doctor/results/:assignmentId/publish' },
    });
    return res.json({
      ok: true,
      assignmentId: idToString(assignmentId),
      resultsPublished: true,
    });
  })
);

app.patch(
  '/grades/:assignmentId/publish',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });

    await db.collection('assignments').updateOne(
      { _id: assignmentId },
      { $set: { resultsPublished: true, resultsPublishedAt: new Date(), updatedAt: new Date() } }
    );

    await logAudit({
      actor: req.user,
      action: 'results.publish',
      targetType: 'assignment',
      targetId: idToString(assignmentId),
      meta: { route: '/grades/:assignmentId/publish' },
    });
    return res.json({
      published: true,
      student_notified: false,
      assignmentId: idToString(assignmentId),
    });
  })
);

app.get(
  '/grades/student',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const submissionsRaw = await db
      .collection('submissions')
      .find({ studentId: { $in: userIdAlternatives(req.user.id) }, status: 'graded' })
      .sort({ updatedAt: -1 })
      .toArray();
    const assignmentIds = submissionsRaw
      .map((s) => getSubmissionAssignmentObjectId(s))
      .filter(Boolean);
    const assignments = assignmentIds.length
      ? await db.collection('assignments').find({ _id: { $in: assignmentIds } }).toArray()
      : [];
    const byAssignmentId = new Map(assignments.map((a) => [idToString(a._id), a]));
    const visible = submissionsRaw.filter((s) => {
      const assignment = byAssignmentId.get(idToString(getSubmissionAssignmentObjectId(s)));
      return isPublishedForStudents(assignment);
    });

    const grades = visible.map((s) => {
      const assignment = byAssignmentId.get(idToString(getSubmissionAssignmentObjectId(s)));
      const totalMark = Number(assignment?.totalMark ?? 100);
      const score = Number(s.score ?? 0);
      return {
        submission_id: idToString(s._id),
        assignment_id: idToString(getSubmissionAssignmentObjectId(s)),
        title: assignment?.title || s.assignmentTitle || 'Untitled',
        score,
        total_mark: totalMark,
        percentage: totalMark > 0 ? Number(((score / totalMark) * 100).toFixed(2)) : 0,
        ai_score: typeof s.ai_score === 'number' ? s.ai_score : null,
        feedback: s.feedback || '',
      };
    });
    const totalScore = grades.reduce((sum, g) => sum + g.score, 0);
    const aiScores = grades.map((g) => g.ai_score).filter((v) => typeof v === 'number');
    const aiScore = aiScores.length ? Number((aiScores.reduce((a, b) => a + b, 0) / aiScores.length).toFixed(2)) : null;

    return res.json({
      grades,
      total_score: totalScore,
      ai_score: aiScore,
    });
  })
);

app.get(
  '/doctor/profile',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const userId = parseObjectId(req.user.id);
    const user = userId ? await db.collection('users').findOne({ _id: userId }) : null;

      const ownershipQuery = req.user.role === 'admin' ? {} : doctorOwnershipFilter(req.user);
      const assignments = await db.collection('assignments').find(ownershipQuery).toArray();
      const assignmentDocs = assignments.filter((a) => !isExamAssignment(a));
      const examDocs = assignments.filter(isExamAssignment);
      const assignmentIds = assignments.flatMap((a) => [a._id, String(a._id)]);
    const submissions = assignmentIds.length
      ? await db.collection('submissions').find({ assignmentId: { $in: assignmentIds } }).toArray()
      : [];

      const activeExams = examDocs.filter((a) => new Date(a.dueDate) >= new Date()).length;
    const pendingGrading = submissions.filter((s) => s.status !== 'graded').length;
    const students = new Set(submissions.map((s) => idToString(s.studentId)).filter(Boolean)).size;

    return res.json({
      user: {
        id: req.user.id,
        name: user?.name || req.user.name || '',
        email: user?.email || req.user.email || '',
        role: user?.role || req.user.role || 'doctor',
        department: user?.department || '',
      },
      stats: {
        activeExams,
          assignments: assignmentDocs.length,
        students,
        pendingGrading,
      },
      courses: Array.isArray(user?.courses) ? user.courses : [],
    });
  })
);

app.put(
  '/doctor/profile',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { value, error } = doctorProfileUpdateSchema.validate(req.body, {
      allowUnknown: false,
      stripUnknown: true,
    });
    if (error) return res.status(400).json({ message: error.message });

    const userId = parseObjectId(req.user.id);
    if (!userId) return res.status(400).json({ message: 'Invalid user id in token' });

    const updates = {
      updatedAt: new Date(),
    };
    if (Object.prototype.hasOwnProperty.call(value, 'department')) {
      updates.department = String(value.department || '').trim();
    }
    if (Object.prototype.hasOwnProperty.call(value, 'courses')) {
      const uniqueCourses = [...new Set((value.courses || []).map((c) => String(c).trim()).filter(Boolean))];
      updates.courses = uniqueCourses;
    }

    const result = await db.collection('users').findOneAndUpdate(
      { _id: userId },
      { $set: updates },
      { returnDocument: 'after' }
    );
    const doctor = unwrapFindOneAndUpdateResult(result);
    if (!doctor) return res.status(404).json({ message: 'Doctor not found' });

    return res.json({
      message: 'Profile updated',
      doctor: {
        id: idToString(doctor._id),
        name: doctor.name || '',
        email: doctor.email || '',
        role: doctor.role || req.user.role || 'doctor',
        department: doctor.department || '',
        courses: Array.isArray(doctor.courses) ? doctor.courses : [],
      },
    });
  })
);

app.get(
  '/student/exams/:assignmentId/questions',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    if (!assignment) return res.status(404).json({ message: 'Assignment not found' });

    const questions = Array.isArray(assignment.questions) && assignment.questions.length
      ? assignment.questions.map((q, idx) => ({
          id: q.id ?? idx + 1,
          text: q.text || '',
          type: q.type || 'essay',
          points: q.points ?? 1,
          options: Array.isArray(q.options) ? q.options : [],
        }))
      : [
          {
            id: 1,
            text: assignment.assignmentText || assignment.description || 'Question 1',
            type: 'essay',
            points: assignment.totalMark ?? 1,
            options: [],
          },
        ];

    const studentFilter = { studentId: { $in: userIdAlternatives(req.user.id) }, assignmentId };
    const existingSubmission = await db.collection('submissions').findOne(studentFilter);
    const answers = Array.isArray(existingSubmission?.answers) ? existingSubmission.answers : [];

    return res.json({
      assignmentId: idToString(assignment._id),
      title: assignment.title || 'Untitled exam',
      totalQuestions: questions.length,
      questions,
      answers,
      status: existingSubmission?.status || 'not_started',
      submissionId: existingSubmission ? idToString(existingSubmission._id) : null,
    });
  })
);

app.post(
  '/student/exams/:assignmentId/questions/:questionId/answer',
  auth,
  allowRoles('student'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    if (!assignment) return res.status(404).json({ message: 'Assignment not found' });

    const questionId = Number(req.params.questionId);
    if (Number.isNaN(questionId)) return res.status(400).json({ message: 'Invalid question id' });

    const answerText = String(req.body.answer || req.body.answerText || '').trim();
    const uploadedFiles = pickUploadedFiles(req.files);
    const uploaded = uploadedFiles[0] || null;
    if (!answerText && !uploadedFiles.length) {
      return res.status(400).json({ message: 'Provide answer text or upload a supporting file' });
    }
    if (uploadedFiles.length) {
      const validType = validateUploadFiles(uploadedFiles);
      if (!validType.ok) return res.status(400).json({ message: validType.message });
    }

    const studentFilter = { studentId: { $in: userIdAlternatives(req.user.id) }, assignmentId };
    const existingSubmission = await db.collection('submissions').findOne(studentFilter);
    const answers = Array.isArray(existingSubmission?.answers) ? [...existingSubmission.answers] : [];
    const idx = answers.findIndex((a) => Number(a.question_id) === questionId);
    const nextAnswer = {
      question_id: questionId,
      answer: answerText,
      file: uploaded
        ? {
            ...fileMetadata(uploaded),
          }
        : (idx >= 0 ? answers[idx].file || null : null),
      files: uploadedFiles.length
        ? uploadedFiles.map(fileMetadata)
        : (idx >= 0 ? answers[idx].files || [] : []),
      updatedAt: new Date(),
    };
    if (idx >= 0) answers[idx] = { ...answers[idx], ...nextAnswer };
    else answers.push(nextAnswer);

    const now = new Date();
    const studentObjectId = parseObjectId(req.user.id);
    if (existingSubmission) {
      await db.collection('submissions').updateOne(
        { _id: existingSubmission._id },
        {
          $set: {
            answers,
            answerText: answers.map((a) => a.answer).filter(Boolean).join('\n\n'),
            studentName: pickDisplayName(req.user.name, req.user.email),
            studentEmail: req.user.email,
            status: existingSubmission.status === 'graded' ? 'graded' : 'in_progress',
            updatedAt: now,
          },
        }
      );
      return res.json({
        ok: true,
        submissionId: idToString(existingSubmission._id),
        status: existingSubmission.status === 'graded' ? 'graded' : 'in_progress',
        savedQuestionId: questionId,
      });
    }

    const doc = {
      assignmentId,
      assignmentTitle: assignment.title,
      studentId: studentObjectId || req.user.id,
      studentName: pickDisplayName(req.user.name, req.user.email),
      studentEmail: req.user.email,
      answerText: answers.map((a) => a.answer).filter(Boolean).join('\n\n'),
      answers,
      status: 'in_progress',
      score: null,
      createdAt: now,
      updatedAt: now,
    };
    const result = await db.collection('submissions').insertOne(doc);
    doc._id = result.insertedId;
    return res.status(201).json({
      ok: true,
      submissionId: idToString(doc._id),
      status: doc.status,
      savedQuestionId: questionId,
    });
  })
);

app.post(
  '/student/exams/:assignmentId/online-submit',
  auth,
  allowRoles('student'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.assignmentId);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });

    const existingSubmission = await db.collection('submissions').findOne({
      studentId: { $in: userIdAlternatives(req.user.id) },
      assignmentId,
    });
    if (!existingSubmission) {
      return res.status(400).json({ message: 'No draft submission found. Save at least one answer first.' });
    }
    if (existingSubmission.status === 'graded') {
      return res.status(400).json({ message: 'Submission already graded' });
    }

    await db.collection('submissions').updateOne(
      { _id: existingSubmission._id },
      { $set: { status: 'submitted', updatedAt: new Date() } }
    );

    setImmediate(() => {
      runSubmissionPipeline({ submissionId: idToString(existingSubmission._id) }).catch((err) => {
        console.error(
          `[pipeline] submission_id=${idToString(existingSubmission._id)} error=${err.message || 'unknown error'}`
        );
      });
    });

    return res.json({
      ok: true,
      submissionId: idToString(existingSubmission._id),
      status: 'submitted',
    });
  })
);

app.put(
  '/users/:id/role',
  auth,
  allowRoles('admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid user id' });
    const role = String(req.body.role || '');
    if (!['student', 'doctor', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    const result = await db
      .collection('users')
      .findOneAndUpdate(
        { _id },
        { $set: { role, updatedAt: new Date() } },
        { returnDocument: 'after' }
      );
    const updated = unwrapFindOneAndUpdateResult(result);
    if (!updated) return res.status(404).json({ message: 'User not found' });
    await logAudit({
      actor: req.user,
      action: 'admin.user.role.update',
      targetType: 'user',
      targetId: idToString(updated._id),
      meta: { role },
    });
    return res.json(okUser(updated));
  })
);

app.put(
  '/admin/users/:id/profile',
  auth,
  allowRoles('admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid user id' });

    const role = req.body.role === undefined ? undefined : String(req.body.role || '');
    if (role !== undefined && !['student', 'doctor', 'admin'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    const updates = { updatedAt: new Date() };
    if (req.body.name !== undefined) updates.name = String(req.body.name || '').trim();
    if (req.body.department !== undefined) updates.department = String(req.body.department || '').trim();
    if (req.body.phone !== undefined) updates.phone = String(req.body.phone || '').trim();
    if (req.body.courses !== undefined) {
      if (!Array.isArray(req.body.courses)) {
        return res.status(400).json({ message: 'courses must be an array of strings' });
      }
      updates.courses = [...new Set(req.body.courses.map((c) => String(c || '').trim()).filter(Boolean))];
    }
    if (role !== undefined) updates.role = role;

    const result = await db.collection('users').findOneAndUpdate(
      { _id },
      { $set: updates },
      { returnDocument: 'after' }
    );
    const updated = unwrapFindOneAndUpdateResult(result);
    if (!updated) return res.status(404).json({ message: 'User not found' });
    await logAudit({
      actor: req.user,
      action: 'admin.user.profile.update',
      targetType: 'user',
      targetId: idToString(updated._id),
      meta: { role: updated.role || '' },
    });

    return res.json({
      message: 'User profile updated',
      user: {
        id: idToString(updated._id),
        name: updated.name || '',
        email: updated.email || '',
        role: updated.role || '',
        department: updated.department || '',
        phone: updated.phone || '',
        courses: Array.isArray(updated.courses) ? updated.courses : [],
      },
    });
  })
);

app.get(
  '/admin/users',
  auth,
  allowRoles('admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const [users, total] = await Promise.all([
      db.collection('users').find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('users').countDocuments({}),
    ]);
    const items = users.map((u) => ({
      id: idToString(u._id),
      name: u.name || '',
      email: u.email || '',
      role: u.role || '',
      department: u.department || '',
      active: u.active !== false,
      createdAt: u.createdAt || null,
    }));
    return res.json({
      users: items,
      total,
      ...buildPaginatedResponse({ items, total, page, limit }).pagination,
    });
  })
);

app.patch(
  '/admin/users/:id/status',
  auth,
  allowRoles('admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid user id' });
    const active = Boolean(req.body.active);
    const result = await db.collection('users').findOneAndUpdate(
      { _id },
      { $set: { active, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );
    const user = unwrapFindOneAndUpdateResult(result);
    if (!user) return res.status(404).json({ message: 'User not found' });
    await logAudit({
      actor: req.user,
      action: active ? 'admin.user.activate' : 'admin.user.deactivate',
      targetType: 'user',
      targetId: idToString(user._id),
      meta: { active: user.active !== false },
    });
    return res.json({
      updated: true,
      user: {
        id: idToString(user._id),
        active: user.active !== false,
      },
    });
  })
);

app.get(
  '/admin/analytics',
  auth,
  allowRoles('admin'),
  asyncRoute(async (_req, res) => {
    const db = getDbOrFail();
    const [assignments, submissions, users] = await Promise.all([
      db.collection('assignments').find({}).toArray(),
      db.collection('submissions').find({}).toArray(),
      db.collection('users').find({}).toArray(),
    ]);
    const totalExams = assignments.filter((a) => isExamAssignment(a)).length;
    const graded = submissions.filter((s) => typeof s.score === 'number');
    const avgScore = graded.length
      ? Number((graded.reduce((sum, s) => sum + Number(s.score || 0), 0) / graded.length).toFixed(2))
      : 0;
    return res.json({
      totalExams,
      avgScore,
      totalAssignments: assignments.length,
      totalSubmissions: submissions.length,
      totalUsers: users.length,
    });
  })
);

app.get(
  '/admin/audit-logs',
  auth,
  allowRoles('admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const { page, limit, skip } = parsePagination(req.query);
    const [logs, total] = await Promise.all([
      db.collection('audit_logs').find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('audit_logs').countDocuments({}),
    ]);
    const items = logs.map((l) => ({
      id: idToString(l._id),
      actorId: l.actorId || '',
      actorEmail: l.actorEmail || '',
      actorRole: l.actorRole || '',
      action: l.action || '',
      targetType: l.targetType || '',
      targetId: l.targetId || '',
      meta: l.meta || {},
      createdAt: l.createdAt || null,
    }));
    return res.json(buildPaginatedResponse({ items, total, page, limit }));
  })
);

app.post(
  '/ai-detection',
  auth,
  asyncRoute(async (req, res) => {
    const text = String(req.body.text || '');
    if (!text.trim()) return res.status(400).json({ message: 'text is required' });

    const localScore = Math.min(0.95, Math.max(0.05, text.length / 500));
    const localPrediction = localScore > 0.5 ? 'AI' : 'Human';

    const localFallbackResponse = (reason) => ({
      ok: true,
      degraded: true,
      reason,
      source: 'local-fallback',
      prediction: localPrediction,
      aiScore: Number(localScore.toFixed(2)),
    });

    if (aiDetectionEndpoint) {
      try {
        const response = await fetch(aiDetectionEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (allowAiFallback) {
            return res.json(localFallbackResponse('upstream_non_200'));
          }
          return res.status(response.status).json({
            message: 'AI detection failed',
            details: payload,
          });
        }
        return res.json({
          ok: true,
          source: aiDetectionEndpoint,
          ...normalizeAiDetectionResult(payload),
        });
      } catch (err) {
        if (allowAiFallback) {
          return res.json(localFallbackResponse('upstream_unreachable'));
        }
        return res.status(502).json({
          message: 'AI detection service unavailable',
          details: err.message,
          source: aiDetectionEndpoint,
        });
      }
    }

    return res.json({
      ...localFallbackResponse('upstream_not_configured'),
      degraded: false,
      source: 'local-mock',
    });
  })
);

app.get(
  '/grading/health',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (_req, res) => {
    if (!gradingApiUrl) {
      return res.status(503).json({ message: 'GRADING_API_URL is not configured' });
    }
    try {
      const response = await fetch(`${gradingApiUrl}/health`);
      const payload = await response.json().catch(() => ({}));
      return res.status(response.status).json(payload);
    } catch (err) {
      return res.status(502).json({ message: 'Grading service unavailable', details: err.message });
    }
  })
);

app.get(
  '/doctor/materials',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const course = normalizeCourseName(req.query.course);
    const doctorIds = buildIdMatchValues(req.user.id);
    const query = {
      ...(req.user.role === 'admin' ? {} : { doctorId: { $in: doctorIds } }),
      ...(course ? { course } : {}),
    };
    const materials = await db.collection('course_materials').find(query).sort({ createdAt: -1 }).toArray();
    return res.json({ items: buildMaterialSummary(materials) });
  })
);

app.post(
  '/doctor/materials',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const course = normalizeCourseName(req.body.course || req.body.course_id || req.body.courseId);
    if (!course) {
      return res.status(400).json({ message: "Missing 'course'." });
    }

    const files = (req.files || []).filter((f) => /^(files|file|material|materials|images|image)(\[\])?(\d+)?$/i.test(f.fieldname));
    const materialText = String(req.body.materialText || req.body.text || req.body.content || '').trim();
    if (!files.length && !materialText) {
      return res.status(400).json({ message: "Provide material files or 'materialText'." });
    }

    const now = new Date();
    let gradingPayload = null;
    let gradingUploadStatus = 'skipped';
    let gradingUploadError = null;

    if (gradingApiUrl && files.length) {
      const form = new FormData();
      form.append('course_id', course);
      for (const file of files) {
        form.append('files', new Blob([file.buffer], { type: file.mimetype }), file.originalname);
      }
      try {
        const response = await fetch(`${gradingApiUrl}/upload-material`, { method: 'POST', body: form });
        gradingPayload = await response.json().catch(() => ({}));
        gradingUploadStatus = response.ok ? 'uploaded' : 'failed';
        if (!response.ok) gradingUploadError = gradingPayload;
      } catch (err) {
        gradingUploadStatus = 'failed';
        gradingUploadError = err.message;
      }
    }

    const doc = {
      doctorId: parseObjectId(req.user.id) || req.user.id,
      doctorEmail: req.user.email || '',
      course,
      title: req.body.title || req.body.materialName || req.body.name || `${course} material`,
      description: req.body.description || '',
      materialText,
      files: files.map((file) => ({
        ...fileMetadata(file),
        uploadedAt: now,
      })),
      gradingUploadStatus,
      gradingUploadError,
      gradingPayload,
      createdAt: now,
      updatedAt: now,
    };
    const result = await db.collection('course_materials').insertOne(doc);

    return res.status(201).json({
      message: 'Course material saved',
      material: buildMaterialSummary([{ ...doc, _id: result.insertedId }])[0],
      gradingUploadStatus,
    });
  })
);

app.delete(
  '/doctor/materials/:id',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid material id' });
    const doctorIds = buildIdMatchValues(req.user.id);
    const query = {
      _id,
      ...(req.user.role === 'admin' ? {} : { doctorId: { $in: doctorIds } }),
    };
    const result = await db.collection('course_materials').deleteOne(query);
    if (!result.deletedCount) return res.status(404).json({ message: 'Material not found' });
    return res.json({ message: 'Course material deleted' });
  })
);

app.post(
  '/grading/upload-material',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    if (!gradingApiUrl) {
      return res.status(503).json({ message: 'GRADING_API_URL is not configured' });
    }
    const files = (req.files || []).filter((f) => /^(files|file|material|materials)(\[\])?(\d+)?$/i.test(f.fieldname));
    if (!files.length) {
      return res.status(400).json({ message: "Missing files. Use form-data field 'files'." });
    }
    if (!req.body.course_id && !req.body.courseId) {
      return res.status(400).json({ message: "Missing 'course_id'." });
    }

    const form = new FormData();
    form.append('course_id', req.body.course_id || req.body.courseId);
    for (const file of files) {
      form.append('files', new Blob([file.buffer], { type: file.mimetype }), file.originalname);
    }

    try {
      const response = await fetch(`${gradingApiUrl}/upload-material`, { method: 'POST', body: form });
      const payload = await response.json().catch(() => ({}));
      return res.status(response.status).json(payload);
    } catch (err) {
      return res.status(502).json({ message: 'Grading upload-material service unavailable', details: err.message });
    }
  })
);

app.post(
  '/grading/upload-model-answer',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    if (!gradingApiUrl) {
      return res.status(503).json({ message: 'GRADING_API_URL is not configured' });
    }
    const file = pickUploadedFile(req.files);
    if (!file) {
      return res.json({
        ok: true,
        skipped: true,
        message: 'Model answer is optional, so grading model-answer upload was skipped because no file was provided.',
      });
    }
    if (!req.body.questions) {
      return res.status(400).json({ message: "Missing 'questions' JSON string." });
    }

    const form = new FormData();
    form.append('questions', req.body.questions);
    form.append('file', new Blob([file.buffer], { type: file.mimetype }), file.originalname);

    try {
      const response = await fetch(`${gradingApiUrl}/upload-model-answer`, { method: 'POST', body: form });
      const payload = await response.json().catch(() => ({}));
      return res.status(response.status).json(payload);
    } catch (err) {
      return res.status(502).json({ message: 'Grading upload-model-answer service unavailable', details: err.message });
    }
  })
);

app.post(
  '/grading/grade',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    if (!gradingApiUrl) {
      return res.status(503).json({ message: 'GRADING_API_URL is not configured' });
    }
    if (!Array.isArray(req.body.linked_questions)) {
      return res.status(400).json({ message: "'linked_questions' must be an array" });
    }
    try {
      const response = await fetch(`${gradingApiUrl}/grade`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          course_id: req.body.course_id || req.body.courseId || req.body.course || null,
          linked_questions: req.body.linked_questions,
          materials: Array.isArray(req.body.materials) ? req.body.materials : [],
          course_materials: Array.isArray(req.body.course_materials) ? req.body.course_materials : [],
          has_course_material: Boolean(req.body.has_course_material),
          has_model_answer: Boolean(req.body.has_model_answer),
          grading_strategy: req.body.grading_strategy || req.body.gradingStrategy || undefined,
        }),
      });
      const payload = await response.json().catch(() => ({}));
      return res.status(response.status).json(response.ok ? normalizeGradingResult(payload) : payload);
    } catch (err) {
      return res.status(502).json({ message: 'Grading service unavailable', details: err.message });
    }
  })
);

app.post(
  '/vlm/process-exam',
  auth,
  allowRoles('doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    if (!vlmApiUrl) {
      return res.status(503).json({ message: 'VLM_API_URL is not configured' });
    }
    const files = (req.files || []).filter(
      (f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname)
    );
    if (files.length === 0) {
      return res.status(400).json({
        message: "Missing images. Send multipart/form-data with at least one file in field 'images' (also accepted: 'image' or 'file').",
      });
    }

    const form = new FormData();
    for (const file of files) {
      form.append('images', new Blob([file.buffer], { type: file.mimetype }), file.originalname);
    }

    let response;
    try {
      response = await fetch(`${vlmApiUrl}/process-exam`, {
        method: 'POST',
        body: form,
      });
    } catch (err) {
      return res.status(502).json({
        message: 'VLM process-exam service unavailable',
        details: err.message,
      });
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({
        message: 'VLM process-exam failed',
        details: payload,
      });
    }

    return res.json(payload);
  })
);

app.post(
  '/vlm/process-answers',
  auth,
  allowRoles('student', 'doctor', 'admin'),
  upload.any(),
  asyncRoute(async (req, res) => {
    if (!vlmApiUrl) {
      return res.status(503).json({ message: 'VLM_API_URL is not configured' });
    }
    const files = (req.files || []).filter(
      (f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname)
    );
    if (files.length === 0) {
      return res.status(400).json({
        message: "Missing images. Send multipart/form-data with at least one file in field 'images' (also accepted: 'image' or 'file').",
      });
    }
    if (!req.body.questions) {
      return res.status(400).json({
        message: "Missing 'questions'. Provide it as a JSON string in form-data (e.g. [{\"id\":1,\"text\":\"...\",\"type\":\"mcq\"}]).",
      });
    }

    const form = new FormData();
    for (const file of files) {
      form.append('images', new Blob([file.buffer], { type: file.mimetype }), file.originalname);
    }
    form.append('questions', req.body.questions);

    let response;
    try {
      response = await fetch(`${vlmApiUrl}/process-answers`, {
        method: 'POST',
        body: form,
      });
    } catch (err) {
      return res.status(502).json({
        message: 'VLM process-answers service unavailable',
        details: err.message,
      });
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({
        message: 'VLM process-answers failed',
        details: payload,
      });
    }

    return res.json(payload);
  })
);

app.post(
  '/vlm/link',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    if (!vlmApiUrl) {
      return res.status(503).json({ message: 'VLM_API_URL is not configured' });
    }
    if (!req.body || !req.body.exam || !req.body.answers) {
      return res.status(400).json({ message: 'exam and answers are required in JSON body' });
    }

    let response;
    try {
      response = await fetch(`${vlmApiUrl}/link`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body),
      });
    } catch (err) {
      return res.status(502).json({
        message: 'VLM link service unavailable',
        details: err.message,
      });
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({
        message: 'VLM link failed',
        details: payload,
      });
    }

    return res.json(payload);
  })
);

// Exam aliases to mirror assignment flow endpoints.
app.get(
  '/exams/:id/submissions',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid exam id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .sort({ createdAt: -1 })
      .toArray();
    const attemptedCount = submissions.length;
    const gradedCount = submissions.filter((s) => s.status === 'graded').length;

    return res.json({
      examId: idToString(assignmentId),
      assignmentId: idToString(assignmentId),
      title: assignment?.title || 'Untitled exam',
      type: getAssignmentType(assignment),
      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark: assignment?.totalMark ?? null,
      attemptedCount,
      submissions: { graded: gradedCount, pending: attemptedCount - gradedCount },
      items: await Promise.all(submissions.map(async (s) => {
        const student = await getStudentIdentityForSubmission(db, s);
        return {
          submissionId: idToString(s._id),
          studentId: student.id,
          studentName: student.name,
          studentEmail: student.email,
          status: s.status === 'graded' ? 'ai_graded' : s.status === 'submitted' ? 'submitted' : s.status,
          score: typeof s.score === 'number' ? s.score : null,
          action: 'review_submission',
        };
      })),
    });
  })
);

app.get(
  '/exams/:id/results',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid exam id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    const submissions = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .toArray();
    const attemptedCount = submissions.length;
    const gradedCount = submissions.filter((s) => typeof s.score === 'number').length;

    return res.json({
      examId: idToString(assignmentId),
      assignmentId: idToString(assignmentId),
      title: assignment?.title || 'Untitled',
      type: getAssignmentType(assignment),
      status: getAssignmentStatus(assignment),
      dueDate: assignment?.dueDate || null,
      totalMark: Number(assignment?.totalMark ?? 20),
      attemptedCount,
      submissions: { graded: gradedCount, pending: attemptedCount - gradedCount },
    });
  })
);

app.patch(
  '/exams/:id/publish',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const assignmentId = parseObjectId(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid exam id' });

    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    if (!isExamAssignment(assignment)) return res.status(404).json({ message: 'Exam not found' });

    await db.collection('assignments').updateOne(
      { _id: assignmentId },
      { $set: { resultsPublished: true, resultsPublishedAt: new Date(), updatedAt: new Date() } }
    );
    await logAudit({
      actor: req.user,
      action: 'results.publish',
      targetType: 'assignment',
      targetId: idToString(assignmentId),
      meta: { route: '/exams/:id/publish' },
    });

    return res.json({
      published: true,
      examId: idToString(assignmentId),
      assignmentId: idToString(assignmentId),
    });
  })
);

app.post('/exams/:id/model-answer', auth, allowRoles('doctor', 'admin'), upload.any(), uploadModelAnswerHandler);
app.post('/api/exams/:id/model-answer', auth, allowRoles('doctor', 'admin'), upload.any(), uploadModelAnswerHandler);

app.use((_req, res) => {
  return sendApiError(res, 404, 'ROUTE_NOT_FOUND', 'Route not found');
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return sendApiError(res, 400, 'FILE_TOO_LARGE', 'File too large. Max size is 10MB.');
  }
  const status = err.status || 500;
  const message = err.message || 'Internal server error';
  const code = status >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_ERROR';
  return sendApiError(res, status, code, message);
});

const start = async () => {
  if (!jwtSecret) {
    throw new Error('JWT_SECRET is required');
  }

  if (mongoUri) {
    try {
      await mongoose.connect(mongoUri);
      console.log('MongoDB connected');
      await ensureIndexes();
      console.log('MongoDB indexes ensured');
    } catch (err) {
      console.error('MongoDB connection failed:', err.message);
      console.error('Server will continue running without DB connection.');
    }
  } else {
    console.warn('MONGO_URI not set. Starting without DB connection.');
  }

  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
};

start().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
