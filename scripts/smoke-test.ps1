param(
  [string]$BaseUrl = "http://localhost:4000"
)

$ErrorActionPreference = "Stop"

function Invoke-Api {
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Url,
    [hashtable]$Headers = $null,
    $Body = $null,
    [string]$ContentType = "application/json"
  )

  try {
    if ($null -ne $Body -and $ContentType -eq "application/json") {
      $resp = Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -ContentType $ContentType -Body ($Body | ConvertTo-Json -Depth 20)
    } elseif ($null -ne $Body) {
      $resp = Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers -ContentType $ContentType -Body $Body
    } else {
      $resp = Invoke-RestMethod -Method $Method -Uri $Url -Headers $Headers
    }
    return [pscustomobject]@{ ok = $true; status = 200; data = $resp }
  } catch {
    $status = $_.Exception.Response.StatusCode.value__
    $bodyText = ""
    try {
      $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
      $bodyText = $reader.ReadToEnd()
    } catch {}
    return [pscustomobject]@{ ok = $false; status = $status; data = $bodyText }
  }
}

function Assert-Status {
  param(
    [string]$Name,
    [object]$Response,
    [int[]]$AllowedStatuses
  )
  if ($AllowedStatuses -contains [int]$Response.status) {
    Write-Output ("PASS  {0} (status={1})" -f $Name, $Response.status)
    return $true
  }
  Write-Output ("FAIL  {0} (status={1}) body={2}" -f $Name, $Response.status, $Response.data)
  return $false
}

$allPassed = $true
$suffix = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$pw = "Passw0rd!"

$health = Invoke-Api -Method GET -Url "$BaseUrl/health"
$allPassed = (Assert-Status -Name "GET /health" -Response $health -AllowedStatuses @(200)) -and $allPassed

$regStudent = Invoke-Api -Method POST -Url "$BaseUrl/api/auth/register" -Body @{ name = "Student"; email = "student_$suffix@example.com"; password = $pw; role = "student" }
$allPassed = (Assert-Status -Name "register student" -Response $regStudent -AllowedStatuses @(200, 201)) -and $allPassed

$regDoctor = Invoke-Api -Method POST -Url "$BaseUrl/api/auth/register" -Body @{ name = "Doctor"; email = "doctor_$suffix@example.com"; password = $pw; role = "doctor" }
$allPassed = (Assert-Status -Name "register doctor" -Response $regDoctor -AllowedStatuses @(200, 201)) -and $allPassed

$regDoctor2 = Invoke-Api -Method POST -Url "$BaseUrl/api/auth/register" -Body @{ name = "Doctor2"; email = "doctor2_$suffix@example.com"; password = $pw; role = "doctor" }
$allPassed = (Assert-Status -Name "register doctor2" -Response $regDoctor2 -AllowedStatuses @(200, 201)) -and $allPassed

$regAdmin = Invoke-Api -Method POST -Url "$BaseUrl/api/auth/register" -Body @{ name = "Admin"; email = "admin_$suffix@example.com"; password = $pw; role = "admin" }
$allPassed = (Assert-Status -Name "register admin" -Response $regAdmin -AllowedStatuses @(200, 201)) -and $allPassed

if (-not $regStudent.ok -or -not $regDoctor.ok -or -not $regDoctor2.ok) {
  Write-Output "Smoke test aborted because registration failed."
  exit 1
}

$hStudent = @{ Authorization = "Bearer $($regStudent.data.token)" }
$hDoctor = @{ Authorization = "Bearer $($regDoctor.data.token)" }
$hDoctor2 = @{ Authorization = "Bearer $($regDoctor2.data.token)" }

$createAssignment = Invoke-Api -Method POST -Url "$BaseUrl/assignments" -Headers $hDoctor -Body @{
  title = "Quiz smoke"
  description = "smoke test"
  totalMark = 10
  dueDate = "2026-12-31T12:00:00.000Z"
}
$allPassed = (Assert-Status -Name "doctor creates assignment" -Response $createAssignment -AllowedStatuses @(200, 201)) -and $allPassed

if (-not $createAssignment.ok) {
  Write-Output "Smoke test aborted because assignment creation failed."
  exit 1
}

$assignmentId = $createAssignment.data._id

$doctor2Assignment = Invoke-Api -Method POST -Url "$BaseUrl/assignments" -Headers $hDoctor2 -Body @{
  title = "Quiz smoke doctor2"
  description = "smoke test doctor2"
  totalMark = 10
  dueDate = "2026-12-31T12:00:00.000Z"
}
$allPassed = (Assert-Status -Name "doctor2 creates assignment" -Response $doctor2Assignment -AllowedStatuses @(200, 201)) -and $allPassed

$createExam = Invoke-Api -Method POST -Url "$BaseUrl/exams" -Headers $hDoctor -Body @{
  title = "Exam smoke"
  description = "smoke exam"
  totalMark = 20
  dueDate = "2026-12-31T12:00:00.000Z"
}
$allPassed = (Assert-Status -Name "doctor creates exam" -Response $createExam -AllowedStatuses @(200, 201)) -and $allPassed

$examId = $null
if ($createExam.ok) {
  $examId = "$($createExam.data._id)"
}

$listAssignmentsDoctor = Invoke-Api -Method GET -Url "$BaseUrl/assignments" -Headers $hDoctor
$allPassed = (Assert-Status -Name "doctor sees assignments endpoint" -Response $listAssignmentsDoctor -AllowedStatuses @(200)) -and $allPassed
if ($listAssignmentsDoctor.ok) {
  $doctorOwnCount = @($listAssignmentsDoctor.data | Where-Object { $_.doctorEmail -eq $regDoctor.data.user.email }).Count
  $doctorOtherCount = @($listAssignmentsDoctor.data | Where-Object { $_.doctorEmail -ne $regDoctor.data.user.email }).Count
  if ($doctorOwnCount -ge 1 -and $doctorOtherCount -eq 0) {
    Write-Output "PASS  doctor assignment scope is restricted to own records"
  } else {
    Write-Output "FAIL  doctor assignment scope leaked records from other doctors"
    $allPassed = $false
  }
}

$studentForbiddenCreate = Invoke-Api -Method POST -Url "$BaseUrl/assignments" -Headers $hStudent -Body @{
  title = "invalid"
  description = "invalid"
  totalMark = 5
  dueDate = "2026-12-31T12:00:00.000Z"
}
$allPassed = (Assert-Status -Name "student forbidden create assignment" -Response $studentForbiddenCreate -AllowedStatuses @(403)) -and $allPassed

$submit = Invoke-Api -Method POST -Url "$BaseUrl/submissions" -Headers $hStudent -ContentType "application/x-www-form-urlencoded" -Body @{
  assignmentId = "$assignmentId"
  answerText = "My answer"
}
$allPassed = (Assert-Status -Name "student submits answer" -Response $submit -AllowedStatuses @(200, 201)) -and $allPassed

if (-not $submit.ok) {
  Write-Output "Smoke test aborted because submission failed."
  exit 1
}

$submissionId = $submit.data._id

$foreignGrade = Invoke-Api -Method PUT -Url "$BaseUrl/submissions/$submissionId/grade" -Headers $hDoctor2 -Body @{ score = 7 }
$allPassed = (Assert-Status -Name "foreign doctor cannot grade" -Response $foreignGrade -AllowedStatuses @(403)) -and $allPassed

$ownerGrade = Invoke-Api -Method PUT -Url "$BaseUrl/submissions/$submissionId/grade" -Headers $hDoctor -Body @{ score = 8 }
$allPassed = (Assert-Status -Name "owner doctor grades" -Response $ownerGrade -AllowedStatuses @(200)) -and $allPassed

$foreignSubmissionById = Invoke-Api -Method GET -Url "$BaseUrl/submissions/$submissionId" -Headers $hDoctor2
$allPassed = (Assert-Status -Name "foreign doctor cannot read submission by id" -Response $foreignSubmissionById -AllowedStatuses @(403)) -and $allPassed

$foreignRead = Invoke-Api -Method GET -Url "$BaseUrl/assignments/$assignmentId/submissions" -Headers $hDoctor2
$allPassed = (Assert-Status -Name "foreign doctor cannot read submissions" -Response $foreignRead -AllowedStatuses @(403)) -and $allPassed

$ownerRead = Invoke-Api -Method GET -Url "$BaseUrl/assignments/$assignmentId/submissions" -Headers $hDoctor
$allPassed = (Assert-Status -Name "owner doctor reads submissions" -Response $ownerRead -AllowedStatuses @(200)) -and $allPassed

$doctorSubmissionsMy = Invoke-Api -Method GET -Url "$BaseUrl/submissions/my" -Headers $hDoctor
$allPassed = (Assert-Status -Name "doctor submissions/my reachable" -Response $doctorSubmissionsMy -AllowedStatuses @(200)) -and $allPassed
if ($doctorSubmissionsMy.ok) {
  $foreignDocs = @($doctorSubmissionsMy.data | Where-Object { $_.assignmentId -ne $assignmentId }).Count
  if ($foreignDocs -eq 0) {
    Write-Output "PASS  doctor submissions/my scope is restricted to own assignments"
  } else {
    Write-Output "FAIL  doctor submissions/my leaked submissions from other assignments"
    $allPassed = $false
  }
}

$doctorExams = Invoke-Api -Method GET -Url "$BaseUrl/doctor/exams" -Headers $hDoctor
$allPassed = (Assert-Status -Name "doctor exams endpoint" -Response $doctorExams -AllowedStatuses @(200)) -and $allPassed
if ($examId) {
  $doctorExamSubmissions = Invoke-Api -Method GET -Url "$BaseUrl/doctor/exams/$examId/submissions" -Headers $hDoctor
  $allPassed = (Assert-Status -Name "doctor exam submissions endpoint" -Response $doctorExamSubmissions -AllowedStatuses @(200)) -and $allPassed

  $doctorExamResults = Invoke-Api -Method GET -Url "$BaseUrl/doctor/exams/$examId/results" -Headers $hDoctor
  $allPassed = (Assert-Status -Name "doctor exam results endpoint" -Response $doctorExamResults -AllowedStatuses @(200)) -and $allPassed
}

$aiCheck = Invoke-Api -Method POST -Url "$BaseUrl/ai-detection" -Headers $hStudent -Body @{ text = "hello from smoke test" }
$allPassed = (Assert-Status -Name "ai-detection reachable or graceful error" -Response $aiCheck -AllowedStatuses @(200, 502)) -and $allPassed

$vlmNoFiles = Invoke-Api -Method POST -Url "$BaseUrl/vlm/process-exam" -Headers $hDoctor
$allPassed = (Assert-Status -Name "vlm/process-exam validation or unavailable" -Response $vlmNoFiles -AllowedStatuses @(400, 503, 502)) -and $allPassed

if ($allPassed) {
  Write-Output "Smoke test completed: ALL CHECKS PASSED."
  exit 0
}

Write-Output "Smoke test completed: SOME CHECKS FAILED."
exit 1
