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

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const port = Number(process.env.PORT) || 4000;
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;
const aiDetectionUrl = (process.env.AI_DETECTION_URL || '').trim();
const allowAiFallback = String(process.env.ALLOW_AI_FALLBACK || 'true').toLowerCase() !== 'false';
const vlmApiUrl = (process.env.VLM_API_URL || '').replace(/\/+$/, '');

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

const pickUploadedFile = (files = []) => {
  if (!Array.isArray(files) || files.length === 0) return null;
  const preferred = files.find((f) => /^(file|image|images)(\[\])?(\d+)?$/i.test(f.fieldname));
  return preferred || files[0] || null;
};

const ensureDoctorAssignmentAccess = (assignment, user) => {
  if (!assignment) return { ok: false, status: 404, message: 'Assignment not found' };
  if (user.role === 'admin') return { ok: true };
  if (user.role === 'doctor' && isSameId(assignment.doctorId, user.id)) return { ok: true };
  return { ok: false, status: 403, message: 'Forbidden' };
};

const auth = async (req, res, next) => {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Missing token' });
    const decoded = jwt.verify(token, jwtSecret);
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
app.post('/api/auth/register', registerHandler);
app.post('/auth/register', registerHandler);
app.post('/api/auth/login', loginHandler);
app.post('/auth/login', loginHandler);

const createAssignmentHandler = asyncRoute(async (req, res) => {
    const { value, error } = assignmentSchema.validate(req.body, {
      allowUnknown: true,
      stripUnknown: true,
    });
    if (error) return res.status(400).json({ message: error.message });

    const db = getDbOrFail();
    const now = new Date();
    const doctorObjectId = parseObjectId(req.user.id);
    const uploaded = pickUploadedFile(req.files);
    const assignmentTextRaw = String(
      req.body.assignmentText ?? req.body.assignment ?? req.body.text ?? ''
    ).trim();
    const assignmentText = assignmentTextRaw || value.assignmentText || '';
    const doc = {
      ...value,
      dueDate: new Date(value.dueDate),
      doctorId: doctorObjectId || req.user.id,
      doctorEmail: req.user.email,
      assignmentText,
      modelAnswer: uploaded
        ? {
            originalName: uploaded.originalname,
            mimeType: uploaded.mimetype,
            size: uploaded.size,
            uploadedAt: now,
          }
        : null,
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

app.get(
  '/assignments',
  auth,
  asyncRoute(async (_req, res) => {
    const db = getDbOrFail();
    const docs = await db.collection('assignments').find({}).sort({ createdAt: -1 }).toArray();
    return res.json(docs);
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
        : {
            doctorId: { $in: userIdAlternatives(req.user.id) },
          };
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
    const uploaded = pickUploadedFile(req.files);
    if (!uploaded) {
      return res.status(400).json({
        message: "Missing upload. Provide model answer file in form-data field 'file' (also accepted: 'image' or 'images').",
      });
    }

    await db.collection('assignments').updateOne(
      { _id },
      {
        $set: {
          modelAnswer: {
            originalName: uploaded.originalname,
            mimeType: uploaded.mimetype,
            size: uploaded.size,
            uploadedAt: new Date(),
          },
          updatedAt: new Date(),
        },
      }
    );

    return res.json({ ok: true, file: uploaded.originalname });
  });

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
    const assignmentId = parseObjectId(req.params.id);
    if (!assignmentId) return res.status(400).json({ message: 'Invalid assignment id' });
    const assignment = await db.collection('assignments').findOne({ _id: assignmentId });
    const access = ensureDoctorAssignmentAccess(assignment, req.user);
    if (!access.ok) return res.status(access.status).json({ message: access.message });
    const docs = await db
      .collection('submissions')
      .find({ assignmentId: { $in: [assignmentId, String(assignmentId)] } })
      .sort({ createdAt: -1 })
      .toArray();
    return res.json(docs);
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

    const now = new Date();
    const studentObjectId = parseObjectId(req.user.id);
    const uploaded = (req.files || []).find((f) => ['file', 'image', 'images'].includes(f.fieldname));
    const doc = {
      assignmentId,
      assignmentTitle: assignment.title,
      studentId: studentObjectId || req.user.id,
      studentEmail: req.user.email,
      answerText: req.body.answerText || '',
      status: 'submitted',
      score: null,
      file: uploaded
        ? {
            originalName: uploaded.originalname,
            mimeType: uploaded.mimetype,
            size: uploaded.size,
          }
        : null,
      createdAt: now,
      updatedAt: now,
    };

    const result = await db.collection('submissions').insertOne(doc);
    doc._id = result.insertedId;
    return res.status(201).json(doc);
  })
);

app.get(
  '/submissions/my',
  auth,
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const query =
      req.user.role === 'student' ? { studentId: { $in: userIdAlternatives(req.user.id) } } : {};
    const docs = await db.collection('submissions').find(query).sort({ createdAt: -1 }).toArray();
    return res.json(docs);
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
    return res.json(doc);
  })
);

app.put(
  '/submissions/:id/grade',
  auth,
  allowRoles('doctor', 'admin'),
  asyncRoute(async (req, res) => {
    const db = getDbOrFail();
    const _id = parseObjectId(req.params.id);
    if (!_id) return res.status(400).json({ message: 'Invalid submission id' });
    const score = Number(req.body.score);
    if (Number.isNaN(score)) return res.status(400).json({ message: 'score is required' });
    const existing = await db.collection('submissions').findOne({ _id });
    if (!existing) return res.status(404).json({ message: 'Submission not found' });

    if (req.user.role === 'doctor') {
      const assignmentObjId =
        existing.assignmentId instanceof ObjectId
          ? existing.assignmentId
          : parseObjectId(existing.assignmentId);
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
      req.user.role === 'admin' ? {} : { doctorId: { $in: userIdAlternatives(req.user.id) } };
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
    return res.json(okUser(updated));
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

    if (aiDetectionUrl) {
      try {
        const response = await fetch(aiDetectionUrl, {
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
          source: aiDetectionUrl,
          ...payload,
        });
      } catch (err) {
        if (allowAiFallback) {
          return res.json(localFallbackResponse('upstream_unreachable'));
        }
        return res.status(502).json({
          message: 'AI detection service unavailable',
          details: err.message,
          source: aiDetectionUrl,
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

app.use((_req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ message: 'File too large. Max size is 10MB.' });
  }
  const status = err.status || 500;
  const message = err.message || 'Internal server error';
  return res.status(status).json({ message });
});

const start = async () => {
  if (!jwtSecret) {
    throw new Error('JWT_SECRET is required');
  }

  if (mongoUri) {
    try {
      await mongoose.connect(mongoUri);
      console.log('MongoDB connected');
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
