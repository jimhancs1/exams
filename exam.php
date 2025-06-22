<?php
/**
 * exam.php
 *
 * This is a single-file online exam platform for both frontend and backend.
 * It handles user authentication (login, signup, logout), exam creation/management
 * for teachers, and exam taking/score viewing for students.
 *
 * It integrates with a MySQL database via the 'connect.php' file.
 * The frontend uses Tailwind CSS for styling, Google Fonts (Inter), and Font Awesome for icons.
 */

// Start session management to handle user login state
session_start();

// Include the database connection file
require_once 'connect.php';

// --- Global Functions ---

/**
 * Redirects the user to a specified URL.
 * @param string $url The URL to redirect to.
 */
function redirect($url) {
    header("Location: " . $url);
    exit();
}

/**
 * Displays a global message (e.g., success or error).
 * Uses session variables to store and retrieve messages.
 * @param string $message The message to display.
 * @param string $type The type of message (e.g., 'success', 'error', 'info').
 */
function display_message() {
    if (isset($_SESSION['message'])) {
        $message = htmlspecialchars($_SESSION['message']);
        $type = htmlspecialchars($_SESSION['message_type'] ?? 'info');
        unset($_SESSION['message']);
        unset($_SESSION['message_type']);

        $bg_class = '';
        $text_class = '';
        switch ($type) {
            case 'success':
                $bg_class = 'bg-green-100 border-green-400 text-green-700';
                break;
            case 'error':
                $bg_class = 'bg-red-100 border-red-400 text-red-700';
                break;
            case 'info':
                $bg_class = 'bg-blue-100 border-blue-400 text-blue-700';
                break;
            case 'warning':
                $bg_class = 'bg-yellow-100 border-yellow-400 text-yellow-700';
                break;
            default:
                $bg_class = 'bg-gray-100 border-gray-400 text-gray-700';
        }
        echo "<div class='p-4 mb-4 text-center rounded-lg border $bg_class' role='alert'>
                <span class='font-medium'>$message</span>
              </div>";
    }
}

/**
 * Sets a global message for display on the next page load.
 * @param string $message The message content.
 * @param string $type The type of message ('success', 'error', 'info', 'warning').
 */
function set_message($message, $type = 'info') {
    $_SESSION['message'] = $message;
    $_SESSION['message_type'] = $type;
}

/**
 * Checks if the user is logged in.
 * @return bool True if logged in, false otherwise.
 */
function is_logged_in() {
    return isset($_SESSION['user_id']);
}

/**
 * Checks if the logged-in user has a specific role.
 * @param string $role The role to check against (e.g., 'teacher', 'student').
 * @return bool True if the user has the specified role, false otherwise.
 */
function is_role($role) {
    return is_logged_in() && $_SESSION['role'] === $role;
}

// --- Authentication Handlers ---

/**
 * Handles user login.
 * @param mysqli $conn Database connection object.
 */
function handle_login($conn) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');

        if (empty($username) || empty($password)) {
            set_message("Please fill in both username and password.", "error");
            redirect('exam.php?page=login');
        }

        // Prepare a statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            // Verify the hashed password
            if (password_verify($password, $user['password'])) {
                // Password is correct, set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                set_message("Welcome, " . htmlspecialchars($user['username']) . "!", "success");
                redirect('exam.php'); // Redirect to dashboard
            } else {
                set_message("Invalid username or password.", "error");
                redirect('exam.php?page=login');
            }
        } else {
            set_message("Invalid username or password.", "error");
            redirect('exam.php?page=login');
        }
        $stmt->close();
    }
}

/**
 * Handles user signup.
 * @param mysqli $conn Database connection object.
 */
function handle_signup($conn) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $username = trim($_POST['username'] ?? '');
        $password = trim($_POST['password'] ?? '');
        $role = $_POST['role'] ?? ''; // 'teacher' or 'student'

        // Basic validation
        if (empty($username) || empty($password) || !in_array($role, ['teacher', 'student'])) {
            set_message("Please fill in all fields correctly.", "error");
            redirect('exam.php?page=signup');
        }
        if (strlen($password) < 6) {
            set_message("Password must be at least 6 characters long.", "error");
            redirect('exam.php?page=signup');
        }

        // Hash the password before storing
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Check if username already exists
        $stmt_check = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt_check->bind_param("s", $username);
        $stmt_check->execute();
        $stmt_check->store_result();

        if ($stmt_check->num_rows > 0) {
            set_message("Username already taken. Please choose a different one.", "error");
            redirect('exam.php?page=signup');
        }
        $stmt_check->close();

        // Insert new user
        $stmt_insert = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
        $stmt_insert->bind_param("sss", $username, $hashed_password, $role);

        if ($stmt_insert->execute()) {
            set_message("Account created successfully! Please log in.", "success");
            redirect('exam.php?page=login');
        } else {
            set_message("Error creating account: " . $conn->error, "error");
            redirect('exam.php?page=signup');
        }
        $stmt_insert->close();
    }
}

/**
 * Logs out the current user by destroying the session.
 */
function handle_logout() {
    $_SESSION = array(); // Clear all session variables
    session_destroy();   // Destroy the session
    set_message("You have been logged out.", "info");
    redirect('exam.php?page=login'); // Redirect to login page
}

// --- Teacher Specific Handlers ---

/**
 * Handles the creation of a new exam.
 * This function also implicitly creates the "marking scheme"
 * by storing correct answers for auto-gradable questions.
 * @param mysqli $conn Database connection object.
 */
function handle_create_exam($conn) {
    if (!is_role('teacher')) {
        set_message("Access denied. Teachers only.", "error");
        redirect('exam.php');
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $teacher_id = $_SESSION['user_id'];
        $title = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $duration = (int)($_POST['duration'] ?? 0);
        $questions_data = json_decode($_POST['questions_json'] ?? '[]', true); // JSON string from textarea

        // Basic validation for exam details and ensuring at least one question is provided
        if (empty($title) || $duration <= 0 || !is_array($questions_data) || empty($questions_data)) {
            set_message("Please fill in exam title, duration, and add at least one valid question.", "error");
            redirect('exam.php?page=create_exam');
        }

        $conn->begin_transaction(); // Start a transaction for atomicity

        try {
            // Insert exam details
            $stmt_exam = $conn->prepare("INSERT INTO exams (teacher_id, title, description, duration_minutes) VALUES (?, ?, ?, ?)");
            $stmt_exam->bind_param("isss", $teacher_id, $title, $description, $duration);
            $stmt_exam->execute();
            $exam_id = $conn->insert_id;
            $stmt_exam->close();

            // Insert questions and answers
            foreach ($questions_data as $q_data) {
                $question_text = trim($q_data['question_text'] ?? '');
                $question_type = trim($q_data['question_type'] ?? ''); // e.g., 'multiple_choice', 'short_answer'
                $answers = $q_data['answers'] ?? []; // Array of answer objects for multiple_choice

                // Validate individual question data
                if (empty($question_text) || !in_array($question_type, ['multiple_choice', 'true_false', 'short_answer'])) {
                    throw new Exception("Invalid or incomplete question data provided for a question.");
                }

                $stmt_question = $conn->prepare("INSERT INTO questions (exam_id, question_text, question_type) VALUES (?, ?, ?)");
                $stmt_question->bind_param("iss", $exam_id, $question_text, $question_type);
                $stmt_question->execute();
                $question_id = $conn->insert_id;
                $stmt_question->close();

                if ($question_type === 'multiple_choice' || $question_type === 'true_false') {
                    if (empty($answers) || !is_array($answers)) {
                         throw new Exception("Multiple choice/True-False questions must have at least one answer option.");
                    }
                    $has_correct_answer = false;
                    foreach ($answers as $a_data) {
                        $answer_text = trim($a_data['answer_text'] ?? '');
                        $is_correct = (bool)($a_data['is_correct'] ?? false);

                        if (empty($answer_text)) {
                            throw new Exception("Answer text cannot be empty for multiple choice/true-false options.");
                        }

                        if ($is_correct) {
                            $has_correct_answer = true;
                        }

                        $stmt_answer = $conn->prepare("INSERT INTO answers (question_id, answer_text, is_correct) VALUES (?, ?, ?)");
                        $stmt_answer->bind_param("isi", $question_id, $answer_text, $is_correct);
                        $stmt_answer->execute();
                        $stmt_answer->close();
                    }
                    if (!$has_correct_answer && ($question_type === 'multiple_choice' || $question_type === 'true_false')) {
                        throw new Exception("At least one correct answer must be provided for multiple choice/true-false questions.");
                    }
                }
                // Short answer questions don't have predefined answers in 'answers' table for auto-marking.
                // Their marking scheme would be external (e.g., manual grading, or keyword matching beyond this scope).
            }

            $conn->commit(); // Commit the transaction if all successful
            set_message("Exam '" . htmlspecialchars($title) . "' created successfully, and marking scheme established!", "success");
            redirect('exam.php?page=teacher_dashboard');

        } catch (Exception $e) {
            $conn->rollback(); // Rollback on error
            set_message("Error creating exam: " . $e->getMessage() . " Please ensure all fields are correctly filled and questions have correct answers selected.", "error");
            redirect('exam.php?page=create_exam');
        }
    }
}

/**
 * Handles deletion of an exam.
 * @param mysqli $conn Database connection object.
 */
function handle_delete_exam($conn) {
    if (!is_role('teacher')) {
        set_message("Access denied. Teachers only.", "error");
        redirect('exam.php');
    }

    $exam_id = (int)($_GET['id'] ?? 0);
    $teacher_id = $_SESSION['user_id'];

    if ($exam_id <= 0) {
        set_message("Invalid exam ID.", "error");
        redirect('exam.php?page=teacher_dashboard');
    }

    // Verify the exam belongs to the teacher
    $stmt = $conn->prepare("SELECT id FROM exams WHERE id = ? AND teacher_id = ?");
    $stmt->bind_param("ii", $exam_id, $teacher_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        set_message("Exam not found or you don't have permission to delete it.", "error");
        redirect('exam.php?page=teacher_dashboard');
    }
    $stmt->close();

    // Delete the exam (ON DELETE CASCADE handles questions, answers, student_exams, student_answers)
    $stmt_delete = $conn->prepare("DELETE FROM exams WHERE id = ?");
    $stmt_delete->bind_param("i", $exam_id);

    if ($stmt_delete->execute()) {
        set_message("Exam deleted successfully.", "success");
    } else {
        set_message("Error deleting exam: " . $conn->error, "error");
    }
    $stmt_delete->close();
    redirect('exam.php?page=teacher_dashboard');
}

// --- Student Specific Handlers ---

/**
 * Handles the submission of an exam by a student.
 * Automatically marks the exam based on the created marking scheme (correct answers).
 * @param mysqli $conn Database connection object.
 */
function handle_submit_exam($conn) {
    if (!is_role('student')) {
        set_message("Access denied. Students only.", "error");
        redirect('exam.php');
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $student_id = $_SESSION['user_id'];
        $exam_id = (int)($_POST['exam_id'] ?? 0);
        $start_time = $_POST['start_time'] ?? ''; // UNIX timestamp of start time

        if ($exam_id <= 0) {
            set_message("Invalid exam submission.", "error");
            redirect('exam.php?page=student_dashboard');
        }

        $conn->begin_transaction();
        try {
            // Check if student has already started this exam, get student_exam_id
            $stmt_se = $conn->prepare("SELECT id, start_time FROM student_exams WHERE student_id = ? AND exam_id = ? AND completed = 0");
            $stmt_se->bind_param("ii", $student_id, $exam_id);
            $stmt_se->execute();
            $result_se = $stmt_se->get_result();
            $student_exam_id = null;
            if ($result_se->num_rows > 0) {
                $row = $result_se->fetch_assoc();
                $student_exam_id = $row['id'];
                // Check if the submitted start_time matches the recorded start_time to prevent re-submission of old attempt
                $recorded_start_timestamp = strtotime($row['start_time']);
                if ($recorded_start_timestamp != $start_time) {
                    throw new Exception("Mismatched exam attempt. Please retry.");
                }
            } else {
                throw new Exception("Exam attempt not found or already completed.");
            }
            $stmt_se->close();

            // Fetch correct answers for scoring (the "marking scheme")
            $correct_answers_map = []; // question_id => correct_answer_id(s) for MC/TF
            $total_auto_gradable_questions = 0; // Counter for questions that can be auto-graded
            $stmt_q = $conn->prepare("SELECT q.id AS question_id, q.question_type, a.id AS answer_id, a.is_correct
                                      FROM questions q LEFT JOIN answers a ON q.id = a.question_id
                                      WHERE q.exam_id = ?");
            $stmt_q->bind_param("i", $exam_id);
            $stmt_q->execute();
            $result_q = $stmt_q->get_result();

            // Populate the marking scheme
            while ($row = $result_q->fetch_assoc()) {
                if (!isset($correct_answers_map[$row['question_id']])) {
                    $correct_answers_map[$row['question_id']] = [
                        'type' => $row['question_type'],
                        'correct_option_ids' => []
                    ];
                    // Increment total auto-gradable questions only for MC or True/False
                    if ($row['question_type'] === 'multiple_choice' || $row['question_type'] === 'true_false') {
                        $total_auto_gradable_questions++;
                    }
                }

                if (($row['question_type'] === 'multiple_choice' || $row['question_type'] === 'true_false') && $row['is_correct']) {
                    $correct_answers_map[$row['question_id']]['correct_option_ids'][] = $row['answer_id'];
                }
            }
            $stmt_q->close();

            $score = 0; // Raw score, number of correct auto-graded questions

            // Clear previous answers for this attempt to prevent duplicates on resubmission
            // This is crucial if a student is redirected back and re-submits due to an error.
            $stmt_delete_old_answers = $conn->prepare("DELETE FROM student_answers WHERE student_exam_id = ?");
            $stmt_delete_old_answers->bind_param("i", $student_exam_id);
            $stmt_delete_old_answers->execute();
            $stmt_delete_old_answers->close();

            // Process submitted answers and calculate score
            foreach ($_POST as $key => $value) {
                if (strpos($key, 'question_') === 0) {
                    $question_id = (int)str_replace('question_', '', $key);

                    if (isset($correct_answers_map[$question_id])) {
                        $q_type = $correct_answers_map[$question_id]['type'];

                        if ($q_type === 'multiple_choice' || $q_type === 'true_false') {
                            $chosen_answer_id = (int)$value;
                            $is_correct_submission = in_array($chosen_answer_id, $correct_answers_map[$question_id]['correct_option_ids']);

                            $stmt_sa = $conn->prepare("INSERT INTO student_answers (student_exam_id, question_id, chosen_answer_id) VALUES (?, ?, ?)");
                            $stmt_sa->bind_param("iii", $student_exam_id, $question_id, $chosen_answer_id);
                            $stmt_sa->execute();
                            $stmt_sa->close();

                            if ($is_correct_submission) {
                                $score++; // Increment score for correctly answered auto-gradable questions
                            }
                        } elseif ($q_type === 'short_answer') {
                            // Store short answer text for potential manual grading later
                            $short_answer_text = trim(htmlspecialchars($value));
                            $stmt_sa = $conn->prepare("INSERT INTO student_answers (student_exam_id, question_id, short_answer_text) VALUES (?, ?, ?)");
                            $stmt_sa->bind_param("iis", $student_exam_id, $question_id, $short_answer_text);
                            $stmt_sa->execute();
                            $stmt_sa->close();
                            // Short answer questions do not contribute to 'score' for auto-grading in this version
                        }
                    }
                }
            }

            // Calculate final score percentage based on auto-gradable questions
            // If total_auto_gradable_questions is 0 (e.g., exam only has short answers), score is 0%
            $final_score_percentage = ($total_auto_gradable_questions > 0) ? ($score / $total_auto_gradable_questions) * 100 : 0;

            // Update student_exams table with score and completion status
            $stmt_update_se = $conn->prepare("UPDATE student_exams SET end_time = NOW(), score = ?, completed = 1 WHERE id = ?");
            $stmt_update_se->bind_param("di", $final_score_percentage, $student_exam_id);
            $stmt_update_se->execute();
            $stmt_update_se->close();

            $conn->commit();
            set_message("Exam submitted successfully! Your automatically graded score: " . round($final_score_percentage, 2) . "%", "success");
            redirect('exam.php?page=view_scores');

        } catch (Exception $e) {
            $conn->rollback();
            set_message("Error submitting exam: " . $e->getMessage(), "error");
            redirect('exam.php?page=take_exam&id=' . $exam_id); // Redirect back to exam if error
        }
    }
}

// --- Main Routing Logic ---

// Determine the current page based on GET parameter, default to 'home' if not logged in, else dashboard
$page = $_GET['page'] ?? '';

if (!is_logged_in()) {
    if ($page === 'signup') {
        handle_signup($conn); // Handle signup form submission
    } else {
        $page = 'login'; // Default to login if not authenticated
        handle_login($conn); // Handle login form submission
    }
} else {
    // Authenticated user routing
    if ($page === 'logout') {
        handle_logout();
    } elseif ($page === 'create_exam') {
        handle_create_exam($conn);
    } elseif ($page === 'delete_exam') {
        handle_delete_exam($conn);
    } elseif ($page === 'submit_exam') {
        handle_submit_exam($conn);
    } elseif (empty($page) || $page === 'home' || $page === 'dashboard') {
        $page = $_SESSION['role'] === 'teacher' ? 'teacher_dashboard' : 'student_dashboard';
    }
    // All other valid pages will be handled by the display logic below
}

// --- HTML Structure and Frontend Display ---
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Online Exam Platform</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Google Fonts - Inter -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <!-- Font Awesome CDN -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" xintegrity="sha512-SnH5WK+bZxgPHs44uWIX+LLJAJ9/2PkPKZ5QiAj6Ta86w+fsb2TkcmfRyVX3pBnMFcV7oQPJkl9QevSCWTKzRzQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f3f4f6; /* Light gray background */
        }
        /* Custom scrollbar for question list if needed */
        .overflow-y-auto::-webkit-scrollbar {
            width: 8px;
        }
        .overflow-y-auto::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        .overflow-y-auto::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 10px;
        }
        .overflow-y-auto::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <nav class="bg-gray-800 p-4 shadow-lg">
        <div class="container mx-auto flex justify-between items-center">
            <a href="exam.php" class="text-white text-2xl font-bold rounded-lg px-3 py-2 hover:bg-gray-700 transition-colors duration-200">
                <i class="fas fa-chalkboard-user mr-2"></i>Exam Platform
            </a>
            <div class="space-x-4">
                <?php if (is_logged_in()): ?>
                    <span class="text-gray-300 text-lg font-medium">
                        <i class="fas fa-user-circle mr-1"></i>Hello, <?php echo htmlspecialchars($_SESSION['username']); ?> (<?php echo htmlspecialchars(ucfirst($_SESSION['role'])); ?>)
                    </span>
                    <?php if (is_role('teacher')): ?>
                        <a href="exam.php?page=create_exam" class="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                            <i class="fas fa-plus-circle mr-1"></i>Create Exam
                        </a>
                        <a href="exam.php?page=teacher_dashboard" class="bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                            <i class="fas fa-clipboard-list mr-1"></i>My Exams
                        </a>
                    <?php else: // Student role ?>
                        <a href="exam.php?page=student_dashboard" class="bg-purple-500 hover:bg-purple-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                            <i class="fas fa-graduation-cap mr-1"></i>Available Exams
                        </a>
                        <a href="exam.php?page=view_scores" class="bg-yellow-500 hover:bg-yellow-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                            <i class="fas fa-chart-bar mr-1"></i>My Scores
                        </a>
                    <?php endif; ?>
                    <a href="exam.php?page=logout" class="bg-red-500 hover:bg-red-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                        <i class="fas fa-sign-out-alt mr-1"></i>Logout
                    </a>
                <?php else: ?>
                    <a href="exam.php?page=login" class="bg-indigo-500 hover:bg-indigo-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                        <i class="fas fa-sign-in-alt mr-1"></i>Login
                    </a>
                    <a href="exam.php?page=signup" class="bg-teal-500 hover:bg-teal-600 text-white font-semibold py-2 px-4 rounded-lg shadow transition-all duration-200">
                        <i class="fas fa-user-plus mr-1"></i>Sign Up
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <main class="flex-grow container mx-auto p-6 md:p-8">
        <?php display_message(); // Display any session messages ?>

        <?php
        // --- Page Content Rendering ---
        switch ($page) {
            case 'login': ?>
                <div class="max-w-md mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-6 text-center">
                        <i class="fas fa-sign-in-alt text-indigo-500 mr-2"></i>Login
                    </h2>
                    <form action="exam.php?page=login" method="POST" class="space-y-5">
                        <div>
                            <label for="username" class="block text-gray-700 text-sm font-medium mb-2">Username:</label>
                            <input type="text" id="username" name="username" required
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 transition duration-200">
                        </div>
                        <div>
                            <label for="password" class="block text-gray-700 text-sm font-medium mb-2">Password:</label>
                            <input type="password" id="password" name="password" required
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 transition duration-200">
                        </div>
                        <button type="submit"
                                class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                            <i class="fas fa-sign-in-alt mr-2"></i>Login
                        </button>
                        <p class="text-center text-gray-600 text-sm mt-4">
                            Don't have an account? <a href="exam.php?page=signup" class="text-indigo-600 hover:underline font-semibold">Sign up here</a>.
                        </p>
                    </form>
                </div>
            <?php break;

            case 'signup': ?>
                <div class="max-w-md mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-6 text-center">
                        <i class="fas fa-user-plus text-teal-500 mr-2"></i>Sign Up
                    </h2>
                    <form action="exam.php?page=signup" method="POST" class="space-y-5">
                        <div>
                            <label for="username" class="block text-gray-700 text-sm font-medium mb-2">Username:</label>
                            <input type="text" id="username" name="username" required
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500 transition duration-200">
                        </div>
                        <div>
                            <label for="password" class="block text-gray-700 text-sm font-medium mb-2">Password:</label>
                            <input type="password" id="password" name="password" required minlength="6"
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500 transition duration-200">
                            <p class="text-xs text-gray-500 mt-1">Minimum 6 characters.</p>
                        </div>
                        <div>
                            <label for="role" class="block text-gray-700 text-sm font-medium mb-2">I am a:</label>
                            <select id="role" name="role" required
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500 transition duration-200">
                                <option value="student">Student</option>
                                <option value="teacher">Teacher</option>
                            </select>
                        </div>
                        <button type="submit"
                                class="w-full bg-teal-600 hover:bg-teal-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                            <i class="fas fa-user-plus mr-2"></i>Sign Up
                        </button>
                        <p class="text-center text-gray-600 text-sm mt-4">
                            Already have an account? <a href="exam.php?page=login" class="text-teal-600 hover:underline font-semibold">Login here</a>.
                        </p>
                    </form>
                </div>
            <?php break;

            case 'teacher_dashboard':
                if (!is_role('teacher')) { redirect('exam.php'); } ?>
                <h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">
                    <i class="fas fa-clipboard-list text-green-600 mr-3"></i>Teacher Dashboard
                </h1>
                <div class="mb-6 flex justify-center space-x-4">
                    <a href="exam.php?page=create_exam" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transition-all duration-300 transform hover:scale-105 flex items-center">
                        <i class="fas fa-plus-circle mr-2"></i>Create New Exam
                    </a>
                </div>

                <div class="bg-white p-8 rounded-lg shadow-xl border border-gray-200 mb-8">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">Your Created Exams</h2>
                    <?php
                    $teacher_id = $_SESSION['user_id'];
                    $stmt = $conn->prepare("SELECT id, title, description, duration_minutes, created_at FROM exams WHERE teacher_id = ? ORDER BY created_at DESC");
                    $stmt->bind_param("i", $teacher_id);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    if ($result->num_rows > 0) { ?>
                        <div class="overflow-x-auto">
                            <table class="min-w-full bg-white rounded-lg overflow-hidden shadow-md">
                                <thead class="bg-gray-100 border-b border-gray-300">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Title</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Duration (min)</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Created On</th>
                                        <th class="px-6 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">Actions</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-200">
                                    <?php while ($exam = $result->fetch_assoc()) { ?>
                                        <tr class="hover:bg-gray-50 transition-colors duration-150">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($exam['title']); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($exam['duration_minutes']); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo date('Y-m-d H:i', strtotime($exam['created_at'])); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-center text-sm font-medium space-x-2">
                                                <a href="exam.php?page=exam_results&exam_id=<?php echo $exam['id']; ?>" class="text-indigo-600 hover:text-indigo-900">
                                                    <i class="fas fa-chart-pie mr-1"></i>View Results
                                                </a>
                                                <a href="exam.php?page=delete_exam&id=<?php echo $exam['id']; ?>"
                                                   onclick="return confirm('Are you sure you want to delete this exam and all its associated data?');"
                                                   class="text-red-600 hover:text-red-900">
                                                    <i class="fas fa-trash-alt mr-1"></i>Delete
                                                </a>
                                            </td>
                                        </tr>
                                    <?php } ?>
                                </tbody>
                            </table>
                        </div>
                    <?php } else { ?>
                        <p class="text-center text-gray-600 text-lg mt-8">You haven't created any exams yet. Click "Create New Exam" to get started!</p>
                    <?php }
                    $stmt->close();
                    ?>
                </div>
            <?php break;

            case 'exam_results': // New page for teacher to view student results for a specific exam
                if (!is_role('teacher')) { redirect('exam.php'); }

                $exam_id = (int)($_GET['exam_id'] ?? 0);
                $teacher_id = $_SESSION['user_id'];

                if ($exam_id <= 0) {
                    set_message("Invalid exam ID selected for results.", "error");
                    redirect('exam.php?page=teacher_dashboard');
                }

                // Verify exam belongs to teacher and fetch exam title
                $stmt_exam_title = $conn->prepare("SELECT title FROM exams WHERE id = ? AND teacher_id = ?");
                $stmt_exam_title->bind_param("ii", $exam_id, $teacher_id);
                $stmt_exam_title->execute();
                $exam_title_result = $stmt_exam_title->get_result();
                $exam_title_row = $exam_title_result->fetch_assoc();
                $stmt_exam_title->close();

                if (!$exam_title_row) {
                    set_message("Exam not found or you don't have permission to view results for it.", "error");
                    redirect('exam.php?page=teacher_dashboard');
                }
                $exam_title = htmlspecialchars($exam_title_row['title']);
                ?>
                <h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">
                    <i class="fas fa-chart-pie text-indigo-600 mr-3"></i>Results for "<?php echo $exam_title; ?>"
                </h1>
                <div class="max-w-4xl mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">Student Performance</h2>
                    <?php
                    $stmt_results = $conn->prepare("
                        SELECT u.username, se.score, se.start_time, se.end_time
                        FROM student_exams se
                        JOIN users u ON se.student_id = u.id
                        WHERE se.exam_id = ? AND se.completed = 1
                        ORDER BY se.end_time DESC
                    ");
                    $stmt_results->bind_param("i", $exam_id);
                    $stmt_results->execute();
                    $results_data = $stmt_results->get_result();

                    if ($results_data->num_rows > 0) { ?>
                        <div class="overflow-x-auto">
                            <table class="min-w-full bg-white rounded-lg overflow-hidden shadow-md">
                                <thead class="bg-gray-100 border-b border-gray-300">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Student Username</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Score (%)</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Start Time</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">End Time</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-200">
                                    <?php while ($student_result = $results_data->fetch_assoc()) { ?>
                                        <tr class="hover:bg-gray-50 transition-colors duration-150">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($student_result['username']); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-semibold <?php echo ($student_result['score'] >= 70) ? 'text-green-600' : 'text-red-600'; ?>">
                                                <?php echo htmlspecialchars(round($student_result['score'], 2)); ?>%
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo date('Y-m-d H:i', strtotime($student_result['start_time'])); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo date('Y-m-d H:i', strtotime($student_result['end_time'])); ?></td>
                                        </tr>
                                    <?php } ?>
                                </tbody>
                            </table>
                        </div>
                    <?php } else { ?>
                        <p class="text-center text-gray-600 text-lg mt-8">No students have completed this exam yet.</p>
                    <?php }
                    $stmt_results->close();
                    ?>
                    <div class="mt-8 text-center">
                        <a href="exam.php?page=teacher_dashboard" class="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                            <i class="fas fa-arrow-left mr-2"></i>Back to Dashboard
                        </a>
                    </div>
                </div>
            <?php break;

            case 'create_exam':
                if (!is_role('teacher')) { redirect('exam.php'); } ?>
                <div class="max-w-3xl mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-6 text-center">
                        <i class="fas fa-plus-circle text-blue-600 mr-2"></i>Create New Exam
                    </h2>
                    <form action="exam.php?page=create_exam" method="POST" id="createExamForm" class="space-y-6">
                        <div>
                            <label for="title" class="block text-gray-700 text-sm font-medium mb-2">Exam Title:</label>
                            <input type="text" id="title" name="title" required
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition duration-200">
                        </div>
                        <div>
                            <label for="description" class="block text-gray-700 text-sm font-medium mb-2">Description:</label>
                            <textarea id="description" name="description" rows="3"
                                      class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition duration-200"></textarea>
                        </div>
                        <div>
                            <label for="duration" class="block text-gray-700 text-sm font-medium mb-2">Duration (minutes):</label>
                            <input type="number" id="duration" name="duration" required min="1" value="60"
                                   class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition duration-200">
                        </div>

                        <h3 class="text-2xl font-semibold text-gray-800 mt-8 mb-4 border-b pb-2">Questions</h3>
                        <div id="questionsContainer" class="space-y-6">
                            <!-- Questions will be added here by JavaScript -->
                        </div>

                        <button type="button" id="addQuestionBtn"
                                class="w-full bg-indigo-500 hover:bg-indigo-600 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105 flex items-center justify-center">
                            <i class="fas fa-plus-square mr-2"></i>Add Question
                        </button>

                        <input type="hidden" name="questions_json" id="questionsJsonInput">

                        <button type="submit"
                                class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105 mt-6">
                            <i class="fas fa-save mr-2"></i>Create Exam
                        </button>
                    </form>
                </div>

                <script>
                    let questionCounter = 0;
                    const questionsData = []; // Array to hold question objects

                    /**
                     * Adds a new question block to the form.
                     */
                    function addQuestion() {
                        questionCounter++;
                        const qId = questionCounter;
                        const questionDiv = document.createElement('div');
                        questionDiv.id = `question-${qId}`;
                        questionDiv.className = 'bg-gray-50 p-6 rounded-lg border border-gray-200 shadow-sm relative';
                        questionDiv.innerHTML = `
                            <button type="button" onclick="removeQuestion(${qId})" class="absolute top-3 right-3 text-red-500 hover:text-red-700 text-xl" title="Remove Question">
                                <i class="fas fa-times-circle"></i>
                            </button>
                            <h4 class="text-lg font-semibold text-gray-700 mb-4">Question ${qId}</h4>
                            <div class="mb-4">
                                <label for="question_text_${qId}" class="block text-gray-700 text-sm font-medium mb-2">Question Text:</label>
                                <textarea id="question_text_${qId}" rows="2" required oninput="updateQuestionData(${qId})"
                                          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"></textarea>
                            </div>
                            <div class="mb-4">
                                <label for="question_type_${qId}" class="block text-gray-700 text-sm font-medium mb-2">Question Type:</label>
                                <select id="question_type_${qId}" onchange="toggleAnswerFields(${qId}); updateQuestionData(${qId});"
                                        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400">
                                    <option value="multiple_choice">Multiple Choice</option>
                                    <option value="true_false">True/False</option>
                                    <option value="short_answer">Short Answer</option>
                                </select>
                            </div>
                            <div id="answers_container_${qId}" class="space-y-3 p-4 bg-gray-100 rounded-lg border border-gray-200">
                                <!-- Answers for Multiple Choice/True False -->
                                <h5 class="text-md font-semibold text-gray-700 mb-3">Answers:</h5>
                                <div id="answer_options_${qId}" class="space-y-2">
                                    <!-- Initial multiple choice answers -->
                                    <div class="flex items-center space-x-2">
                                        <input type="radio" name="correct_answer_${qId}" id="answer_is_correct_${qId}_1" value="1" onchange="updateQuestionData(${qId})" class="form-radio h-4 w-4 text-green-500">
                                        <input type="text" id="answer_text_${qId}_1" placeholder="Option A" oninput="updateQuestionData(${qId})" required class="flex-grow px-3 py-2 border border-gray-300 rounded-lg">
                                        <button type="button" onclick="removeAnswer(${qId}, 1)" class="text-red-500 hover:text-red-700"><i class="fas fa-minus-circle"></i></button>
                                    </div>
                                    <div class="flex items-center space-x-2">
                                        <input type="radio" name="correct_answer_${qId}" id="answer_is_correct_${qId}_2" value="2" onchange="updateQuestionData(${qId})" class="form-radio h-4 w-4 text-green-500">
                                        <input type="text" id="answer_text_${qId}_2" placeholder="Option B" oninput="updateQuestionData(${qId})" required class="flex-grow px-3 py-2 border border-gray-300 rounded-lg">
                                        <button type="button" onclick="removeAnswer(${qId}, 2)" class="text-red-500 hover:text-red-700"><i class="fas fa-minus-circle"></i></button>
                                    </div>
                                </div>
                                <button type="button" onclick="addAnswerOption(${qId})"
                                        class="mt-3 px-4 py-2 bg-purple-500 hover:bg-purple-600 text-white text-sm font-medium rounded-lg flex items-center">
                                    <i class="fas fa-plus mr-1"></i>Add Option
                                </button>
                            </div>
                        `;
                        document.getElementById('questionsContainer').appendChild(questionDiv);

                        // Initialize data for this new question
                        questionsData.push({
                            id: qId,
                            question_text: '',
                            question_type: 'multiple_choice',
                            answers: [
                                { id: 1, answer_text: '', is_correct: false },
                                { id: 2, answer_text: '', is_correct: false }
                            ]
                        });
                        updateQuestionsJson(); // Update JSON input immediately
                    }

                    /**
                     * Removes a question block from the form and updates the data model.
                     * @param {number} qId The ID of the question to remove.
                     */
                    function removeQuestion(qId) {
                        document.getElementById(`question-${qId}`).remove();
                        const index = questionsData.findIndex(q => q.id === qId);
                        if (index !== -1) {
                            questionsData.splice(index, 1);
                        }
                        updateQuestionsJson();
                    }

                    /**
                     * Toggles the visibility of answer fields based on question type.
                     * @param {number} qId The ID of the question.
                     */
                    function toggleAnswerFields(qId) {
                        const typeSelect = document.getElementById(`question_type_${qId}`);
                        const answersContainer = document.getElementById(`answers_container_${qId}`);
                        if (typeSelect.value === 'short_answer') {
                            answersContainer.classList.add('hidden');
                            // Clear answers data for short answer questions in the model
                            const qIndex = questionsData.findIndex(q => q.id === qId);
                            if (qIndex !== -1) {
                                questionsData[qIndex].answers = [];
                            }
                        } else {
                            answersContainer.classList.remove('hidden');
                            // Ensure answers exist in model if switching back from short answer, and re-render them
                            const qIndex = questionsData.findIndex(q => q.id === qId);
                            if (qIndex !== -1 && questionsData[qIndex].answers.length === 0) {
                                // Re-add default answers if none exist
                                questionsData[qIndex].answers = [
                                    { id: 1, answer_text: '', is_correct: false },
                                    { id: 2, answer_text: '', is_correct: false }
                                ];
                                // Re-render the HTML options
                                const answerOptionsDiv = document.getElementById(`answer_options_${qId}`);
                                answerOptionsDiv.innerHTML = ''; // Clear existing
                                questionsData[qIndex].answers.forEach((ans) => {
                                    renderAnswerOption(qId, ans.id, ans.answer_text, ans.is_correct);
                                });
                            }
                        }
                        updateQuestionsJson(); // Update JSON input after toggle
                    }

                    let answerCounters = {}; // To keep track of unique answer IDs per question

                    /**
                     * Adds a new answer option input field for a multiple choice/true false question.
                     * @param {number} qId The ID of the question.
                     */
                    function addAnswerOption(qId) {
                        if (!answerCounters[qId]) {
                            // Find the maximum existing answer ID for this question
                            const existingAnswers = document.querySelectorAll(`#answer_options_${qId} input[type="text"]`);
                            let maxId = 0;
                            if (existingAnswers.length > 0) {
                                existingAnswers.forEach(input => {
                                    const id = parseInt(input.id.split('_')[3]);
                                    if (id > maxId) maxId = id;
                                });
                            }
                            answerCounters[qId] = maxId + 1;
                        } else {
                            answerCounters[qId]++;
                        }
                        const answerId = answerCounters[qId];
                        renderAnswerOption(qId, answerId, '', false);

                        const qIndex = questionsData.findIndex(q => q.id === qId);
                        if (qIndex !== -1) {
                            questionsData[qIndex].answers.push({ id: answerId, answer_text: '', is_correct: false });
                        }
                        updateQuestionsJson();
                    }

                    /**
                     * Renders an individual answer option HTML.
                     * @param {number} qId The ID of the question.
                     * @param {number} answerId The ID of the answer option.
                     * @param {string} answerText The text of the answer.
                     * @param {boolean} isCorrect Whether this answer is correct.
                     */
                    function renderAnswerOption(qId, answerId, answerText, isCorrect) {
                        const answerOptionsDiv = document.getElementById(`answer_options_${qId}`);
                        const answerDiv = document.createElement('div');
                        answerDiv.className = 'flex items-center space-x-2';
                        answerDiv.id = `answer-option-${qId}-${answerId}`;
                        answerDiv.innerHTML = `
                            <input type="radio" name="correct_answer_${qId}" id="answer_is_correct_${qId}_${answerId}" value="${answerId}"
                                onchange="updateQuestionData(${qId})" ${isCorrect ? 'checked' : ''} class="form-radio h-4 w-4 text-green-500">
                            <input type="text" id="answer_text_${qId}_${answerId}" placeholder="Option ${answerId}" value="${answerText}"
                                oninput="updateQuestionData(${qId})" required class="flex-grow px-3 py-2 border border-gray-300 rounded-lg">
                            <button type="button" onclick="removeAnswer(${qId}, ${answerId})" class="text-red-500 hover:text-red-700">
                                <i class="fas fa-minus-circle"></i>
                            </button>
                        `;
                        answerOptionsDiv.appendChild(answerDiv);
                    }

                    /**
                     * Removes an answer option from a question.
                     * @param {number} qId The ID of the question.
                     * @param {number} answerId The ID of the answer to remove.
                     */
                    function removeAnswer(qId, answerId) {
                        const answerOptionDiv = document.getElementById(`answer-option-${qId}-${answerId}`);
                        if (answerOptionDiv) {
                            answerOptionDiv.remove();
                            const qIndex = questionsData.findIndex(q => q.id === qId);
                            if (qIndex !== -1) {
                                questionsData[qIndex].answers = questionsData[qIndex].answers.filter(a => a.id !== answerId);
                            }
                            updateQuestionsJson();
                        }
                    }

                    /**
                     * Updates the data model (questionsData array) for a specific question based on its input fields.
                     * This function is crucial for ensuring the JSON accurately reflects the form state.
                     * @param {number} qId The ID of the question to update.
                     */
                    function updateQuestionData(qId) {
                        const qIndex = questionsData.findIndex(q => q.id === qId);
                        if (qIndex === -1) return;

                        const questionTextElem = document.getElementById(`question_text_${qId}`);
                        const questionTypeElem = document.getElementById(`question_type_${qId}`);

                        questionsData[qIndex].question_text = questionTextElem ? questionTextElem.value : '';
                        questionsData[qIndex].question_type = questionTypeElem ? questionTypeElem.value : 'multiple_choice';

                        const currentQuestionType = questionsData[qIndex].question_type;

                        if (currentQuestionType === 'multiple_choice' || currentQuestionType === 'true_false') {
                            const answers = [];
                            document.querySelectorAll(`#answer_options_${qId} input[type="text"]`).forEach(input => {
                                const ansId = parseInt(input.id.split('_')[3]);
                                const isCorrectRadio = document.getElementById(`answer_is_correct_${qId}_${ansId}`);
                                answers.push({
                                    id: ansId, // Store original ID to match in PHP, though not strictly needed for current backend logic
                                    answer_text: input.value,
                                    is_correct: isCorrectRadio ? isCorrectRadio.checked : false
                                });
                            });
                            questionsData[qIndex].answers = answers;
                        } else {
                            questionsData[qIndex].answers = []; // No answers for short answer
                        }

                        // Debugging: Log the updated question data
                        // console.log(`Question ${qId} data updated:`, questionsData[qIndex]);

                        updateQuestionsJson(); // Always update the hidden JSON input after data changes
                    }

                    /**
                     * Iterates through all existing questions and updates their data in the questionsData array.
                     * This is called before form submission to ensure all latest input is captured.
                     */
                    function updateAllQuestionsData() {
                        document.querySelectorAll('[id^="question-"]').forEach(questionDiv => {
                            const qId = parseInt(questionDiv.id.split('-')[1]);
                            updateQuestionData(qId);
                        });
                    }

                    /**
                     * Updates the hidden input field with the JSON string of all questions data.
                     */
                    function updateQuestionsJson() {
                        document.getElementById('questionsJsonInput').value = JSON.stringify(questionsData);
                        // Debugging: Log the final JSON string
                        // console.log('Questions JSON:', document.getElementById('questionsJsonInput').value);
                    }

                    document.addEventListener('DOMContentLoaded', () => {
                        document.getElementById('addQuestionBtn').addEventListener('click', addQuestion);
                        addQuestion(); // Add first question by default

                        // --- IMPORTANT FIX FOR BUTTON NOT WORKING ---
                        // Ensure all question data is updated right before form submission
                        const createExamForm = document.getElementById('createExamForm');
                        if (createExamForm) {
                            createExamForm.addEventListener('submit', function(event) {
                                // Manually trigger update for all questions before submission
                                // This ensures data from fields that haven't lost focus are included
                                updateAllQuestionsData();

                                // Optional: Add client-side validation here before allowing submission
                                // For example, check if at least one correct answer is selected for MC/TF questions
                                for (const q of questionsData) {
                                    if ((q.question_type === 'multiple_choice' || q.question_type === 'true_false') && q.answers.length > 0) {
                                        const hasCorrect = q.answers.some(a => a.is_correct);
                                        if (!hasCorrect) {
                                            alert(`Question ${q.id}: Please select at least one correct answer.`);
                                            event.preventDefault(); // Prevent form submission
                                            return;
                                        }
                                    }
                                }
                                console.log('Form submitting with JSON:', document.getElementById('questionsJsonInput').value);
                            });
                        }
                        // --- END IMPORTANT FIX ---
                    });
                </script>
            <?php break;

            case 'student_dashboard':
                if (!is_role('student')) { redirect('exam.php'); } ?>
                <h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">
                    <i class="fas fa-graduation-cap text-purple-600 mr-3"></i>Student Dashboard
                </h1>

                <div class="bg-white p-8 rounded-lg shadow-xl border border-gray-200 mb-8">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">Available Exams</h2>
                    <?php
                    $student_id = $_SESSION['user_id'];

                    // Select exams that the student has NOT completed yet
                    $stmt_available = $conn->prepare("
                        SELECT e.id, e.title, e.description, e.duration_minutes, u.username AS teacher_name
                        FROM exams e
                        JOIN users u ON e.teacher_id = u.id
                        LEFT JOIN student_exams se ON e.id = se.exam_id AND se.student_id = ?
                        WHERE se.id IS NULL OR se.completed = 0
                        ORDER BY e.created_at DESC
                    ");
                    $stmt_available->bind_param("i", $student_id);
                    $stmt_available->execute();
                    $result_available = $stmt_available->get_result();

                    if ($result_available->num_rows > 0) { ?>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <?php while ($exam = $result_available->fetch_assoc()) { ?>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md border border-gray-200 flex flex-col justify-between">
                                    <div>
                                        <h3 class="text-xl font-semibold text-gray-800 mb-2"><?php echo htmlspecialchars($exam['title']); ?></h3>
                                        <p class="text-gray-600 text-sm mb-3"><?php echo htmlspecialchars($exam['description']); ?></p>
                                        <p class="text-sm text-gray-700 mb-1"><i class="fas fa-clock mr-1 text-blue-500"></i>Duration: <?php echo htmlspecialchars($exam['duration_minutes']); ?> minutes</p>
                                        <p class="text-sm text-gray-700 mb-4"><i class="fas fa-chalkboard-teacher mr-1 text-green-500"></i>By: <?php echo htmlspecialchars($exam['teacher_name']); ?></p>
                                    </div>
                                    <a href="exam.php?page=take_exam&id=<?php echo $exam['id']; ?>"
                                       class="mt-4 block text-center bg-purple-600 hover:bg-purple-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                                        <i class="fas fa-play-circle mr-2"></i>Take Exam
                                    </a>
                                </div>
                            <?php } ?>
                        </div>
                    <?php } else { ?>
                        <p class="text-center text-gray-600 text-lg mt-8">No new exams available at the moment. Check back later!</p>
                    <?php }
                    $stmt_available->close();
                    ?>
                </div>

                <div class="bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">Your Completed Exams</h2>
                    <?php
                    // Select exams that the student HAS completed
                    $stmt_completed = $conn->prepare("
                        SELECT se.id AS student_exam_id, e.title, e.description, e.duration_minutes,
                               se.start_time, se.end_time, se.score, u.username AS teacher_name
                        FROM student_exams se
                        JOIN exams e ON se.exam_id = e.id
                        JOIN users u ON e.teacher_id = u.id
                        WHERE se.student_id = ? AND se.completed = 1
                        ORDER BY se.end_time DESC
                    ");
                    $stmt_completed->bind_param("i", $student_id);
                    $stmt_completed->execute();
                    $result_completed = $stmt_completed->get_result();

                    if ($result_completed->num_rows > 0) { ?>
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <?php while ($exam_completed = $result_completed->fetch_assoc()) { ?>
                                <div class="bg-gray-50 p-6 rounded-lg shadow-md border border-gray-200 flex flex-col justify-between">
                                    <div>
                                        <h3 class="text-xl font-semibold text-gray-800 mb-2"><?php echo htmlspecialchars($exam_completed['title']); ?></h3>
                                        <p class="text-gray-600 text-sm mb-3"><?php echo htmlspecialchars($exam_completed['description']); ?></p>
                                        <p class="text-sm text-gray-700 mb-1"><i class="fas fa-clock mr-1 text-blue-500"></i>Duration: <?php echo htmlspecialchars($exam_completed['duration_minutes']); ?> minutes</p>
                                        <p class="text-sm text-gray-700 mb-2"><i class="fas fa-chalkboard-teacher mr-1 text-green-500"></i>By: <?php echo htmlspecialchars($exam_completed['teacher_name']); ?></p>
                                        <p class="text-lg font-bold <?php echo ($exam_completed['score'] >= 70) ? 'text-green-600' : 'text-red-600'; ?>"><i class="fas fa-percent mr-1"></i>Score: <?php echo htmlspecialchars(round($exam_completed['score'], 2)); ?>%</p>
                                    </div>
                                    <a href="exam.php?page=view_completed_exam&student_exam_id=<?php echo $exam_completed['student_exam_id']; ?>"
                                       class="mt-4 block text-center bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                                        <i class="fas fa-eye mr-2"></i>View Details
                                    </a>
                                </div>
                            <?php } ?>
                        </div>
                    <?php } else { ?>
                        <p class="text-center text-gray-600 text-lg mt-8">You haven't completed any exams yet.</p>
                    <?php }
                    $stmt_completed->close();
                    ?>
                </div>
            <?php break;

            case 'take_exam':
                if (!is_role('student')) { redirect('exam.php'); }

                $exam_id = (int)($_GET['id'] ?? 0);
                $student_id = $_SESSION['user_id'];

                if ($exam_id <= 0) {
                    set_message("Invalid exam selected.", "error");
                    redirect('exam.php?page=student_dashboard');
                }

                // Check if student has already completed this exam
                $stmt_check_completed = $conn->prepare("SELECT id FROM student_exams WHERE student_id = ? AND exam_id = ? AND completed = 1");
                $stmt_check_completed->bind_param("ii", $student_id, $exam_id);
                $stmt_check_completed->execute();
                if ($stmt_check_completed->get_result()->num_rows > 0) {
                    set_message("You have already completed this exam.", "info");
                    redirect('exam.php?page=view_scores');
                }
                $stmt_check_completed->close();


                // Fetch exam details
                $stmt_exam = $conn->prepare("SELECT id, title, description, duration_minutes FROM exams WHERE id = ?");
                $stmt_exam->bind_param("i", $exam_id);
                $stmt_exam->execute();
                $exam_result = $stmt_exam->get_result();
                $exam = $exam_result->fetch_assoc();
                $stmt_exam->close();

                if (!$exam) {
                    set_message("Exam not found.", "error");
                    redirect('exam.php?page=student_dashboard');
                }

                // Check if exam is already in progress
                $student_exam_id = null;
                $exam_start_time = null;
                $stmt_in_progress = $conn->prepare("SELECT id, start_time FROM student_exams WHERE student_id = ? AND exam_id = ? AND completed = 0");
                $stmt_in_progress->bind_param("ii", $student_id, $exam_id);
                $stmt_in_progress->execute();
                $in_progress_result = $stmt_in_progress->get_result();
                if ($in_progress_result->num_rows > 0) {
                    $row = $in_progress_result->fetch_assoc();
                    $student_exam_id = $row['id'];
                    $exam_start_time = strtotime($row['start_time']);
                } else {
                    // Start new exam attempt
                    $stmt_start = $conn->prepare("INSERT INTO student_exams (student_id, exam_id, start_time, completed) VALUES (?, ?, NOW(), 0)");
                    $stmt_start->bind_param("ii", $student_id, $exam_id);
                    $stmt_start->execute();
                    $student_exam_id = $conn->insert_id;
                    $exam_start_time = time(); // Current time for JS countdown
                    $stmt_start->close();
                }
                $stmt_in_progress->close();


                // Fetch questions for the exam
                $questions = [];
                $stmt_questions = $conn->prepare("SELECT id, question_text, question_type FROM questions WHERE exam_id = ? ORDER BY id ASC");
                $stmt_questions->bind_param("i", $exam_id);
                $stmt_questions->execute();
                $questions_result = $stmt_questions->get_result();

                while ($q = $questions_result->fetch_assoc()) {
                    $question_id = $q['id'];
                    $q['answers'] = []; // Placeholder for answers
                    if ($q['question_type'] === 'multiple_choice' || $q['question_type'] === 'true_false') {
                        // Do NOT fetch is_correct for take_exam page, as per requirement
                        $stmt_answers = $conn->prepare("SELECT id, answer_text FROM answers WHERE question_id = ? ORDER BY id ASC");
                        $stmt_answers->bind_param("i", $question_id);
                        $stmt_answers->execute();
                        $answers_result = $stmt_answers->get_result();
                        while ($a = $answers_result->fetch_assoc()) {
                            $q['answers'][] = $a;
                        }
                        $stmt_answers->close();
                    }
                    $questions[] = $q;
                }
                $stmt_questions->close();

                if (empty($questions)) {
                    set_message("This exam has no questions yet. Please contact the teacher.", "info");
                    redirect('exam.php?page=student_dashboard');
                }
                ?>
                <div class="max-w-4xl mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-4 text-center"><?php echo htmlspecialchars($exam['title']); ?></h2>
                    <p class="text-gray-600 text-center mb-6"><?php echo htmlspecialchars($exam['description']); ?></p>

                    <div class="flex justify-between items-center bg-gray-100 p-4 rounded-lg mb-6 shadow-sm">
                        <span class="text-lg font-medium text-gray-700"><i class="fas fa-clock mr-2 text-blue-500"></i>Time Remaining: <span id="countdown" class="font-bold text-red-600"></span></span>
                        <span class="text-lg font-medium text-gray-700">Total Questions: <span class="font-bold text-green-600"><?php echo count($questions); ?></span></span>
                    </div>

                    <form action="exam.php?page=submit_exam" method="POST" id="examForm" class="space-y-8">
                        <input type="hidden" name="exam_id" value="<?php echo $exam_id; ?>">
                        <input type="hidden" name="start_time" value="<?php echo $exam_start_time; ?>">
                        <input type="hidden" name="student_exam_id" value="<?php echo $student_exam_id; ?>">

                        <?php foreach ($questions as $index => $q): ?>
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200 shadow-sm question-item" id="question_<?php echo $q['id']; ?>">
                                <h4 class="text-xl font-semibold text-gray-800 mb-4">Question <?php echo $index + 1; ?>:</h4>
                                <p class="text-gray-700 text-lg mb-4"><?php echo htmlspecialchars($q['question_text']); ?></p>

                                <?php if ($q['question_type'] === 'multiple_choice' || $q['question_type'] === 'true_false'): ?>
                                    <div class="space-y-3">
                                        <?php foreach ($q['answers'] as $a): ?>
                                            <label class="flex items-center bg-white p-3 rounded-lg border border-gray-300 hover:bg-gray-100 transition-colors duration-150 cursor-pointer">
                                                <input type="radio" name="question_<?php echo $q['id']; ?>" value="<?php echo $a['id']; ?>" required
                                                       class="form-radio h-5 w-5 text-indigo-600 focus:ring-indigo-500">
                                                <span class="ml-3 text-gray-800 text-md"><?php echo htmlspecialchars($a['answer_text']); ?></span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                <?php elseif ($q['question_type'] === 'short_answer'): ?>
                                    <div>
                                        <textarea name="question_<?php echo $q['id']; ?>" rows="4" placeholder="Type your answer here..." required
                                                  class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 transition duration-200"></textarea>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>

                        <button type="submit"
                                class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-4 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105 mt-8">
                            <i class="fas fa-check-circle mr-2"></i>Submit Exam
                        </button>
                    </form>
                </div>

                <script>
                    const examDuration = <?php echo $exam['duration_minutes']; ?>; // in minutes
                    const startTime = <?php echo $exam_start_time; ?>; // UNIX timestamp
                    const countdownElement = document.getElementById('countdown');
                    const examForm = document.getElementById('examForm');

                    function updateCountdown() {
                        const currentTime = Math.floor(Date.now() / 1000); // Current UNIX timestamp
                        const elapsedTime = currentTime - startTime;
                        const remainingSeconds = (examDuration * 60) - elapsedTime;

                        if (remainingSeconds <= 0) {
                            countdownElement.textContent = "00:00:00 - Time's Up!";
                            // Automatically submit the form when time runs out
                            if (examForm) {
                                // Instead of alert, consider a modal or a non-blocking message
                                // alert("Time's up! Your exam will be submitted automatically.");
                                console.log("Time's up! Submitting exam automatically.");
                                examForm.submit();
                            }
                            clearInterval(countdownInterval);
                            return;
                        }

                        const hours = Math.floor(remainingSeconds / 3600);
                        const minutes = Math.floor((remainingSeconds % 3600) / 60);
                        const seconds = remainingSeconds % 60;

                        const displayHours = String(hours).padStart(2, '0');
                        const displayMinutes = String(minutes).padStart(2, '0');
                        const displaySeconds = String(seconds).padStart(2, '0');

                        countdownElement.textContent = `${displayHours}:${displayMinutes}:${displaySeconds}`;
                    }

                    // Update countdown every second
                    const countdownInterval = setInterval(updateCountdown, 1000);
                    updateCountdown(); // Call once immediately to avoid delay
                </script>
            <?php break;

            case 'view_scores':
                if (!is_role('student')) { redirect('exam.php'); } ?>
                <h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">
                    <i class="fas fa-chart-bar text-yellow-600 mr-3"></i>My Exam Scores
                </h1>

                <div class="bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6 text-center">Your Completed Exams</h2>
                    <?php
                    $student_id = $_SESSION['user_id'];
                    $stmt = $conn->prepare("
                        SELECT se.id AS student_exam_id, e.title, e.description, e.duration_minutes,
                               se.start_time, se.end_time, se.score, u.username AS teacher_name
                        FROM student_exams se
                        JOIN exams e ON se.exam_id = e.id
                        JOIN users u ON e.teacher_id = u.id
                        WHERE se.student_id = ? AND se.completed = 1
                        ORDER BY se.end_time DESC
                    ");
                    $stmt->bind_param("i", $student_id);
                    $stmt->execute();
                    $result = $stmt->get_result();

                    if ($result->num_rows > 0) { ?>
                        <div class="overflow-x-auto">
                            <table class="min-w-full bg-white rounded-lg overflow-hidden shadow-md">
                                <thead class="bg-gray-100 border-b border-gray-300">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Exam Title</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">By Teacher</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Duration</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Start Time</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">End Time</th>
                                        <th class="px-6 py-3 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">Score (%)</th>
                                        <th class="px-6 py-3 text-center text-xs font-semibold text-gray-600 uppercase tracking-wider">Action</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-200">
                                    <?php while ($exam_score = $result->fetch_assoc()) { ?>
                                        <tr class="hover:bg-gray-50 transition-colors duration-150">
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($exam_score['title']); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($exam_score['teacher_name']); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo htmlspecialchars($exam_score['duration_minutes']); ?> min</td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo date('Y-m-d H:i', strtotime($exam_score['start_time'])); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600"><?php echo date('Y-m-d H:i', strtotime($exam_score['end_time'])); ?></td>
                                            <td class="px-6 py-4 whitespace-nowrap text-sm font-semibold <?php echo ($exam_score['score'] >= 70) ? 'text-green-600' : 'text-red-600'; ?>">
                                                <?php echo htmlspecialchars(round($exam_score['score'], 2)); ?>%
                                            </td>
                                            <td class="px-6 py-4 whitespace-nowrap text-center text-sm">
                                                <a href="exam.php?page=view_completed_exam&student_exam_id=<?php echo $exam_score['student_exam_id']; ?>"
                                                   class="text-blue-600 hover:text-blue-900">
                                                    <i class="fas fa-eye mr-1"></i>View Answers
                                                </a>
                                            </td>
                                        </tr>
                                    <?php } ?>
                                </tbody>
                            </table>
                        </div>
                    <?php } else { ?>
                        <p class="text-center text-gray-600 text-lg mt-8">You haven't completed any exams yet.</p>
                        <p class="text-center text-gray-600 text-lg mt-2">Go to <a href="exam.php?page=student_dashboard" class="text-purple-600 hover:underline font-semibold">Available Exams</a> to start one!</p>
                    <?php }
                    $stmt->close();
                    ?>
                </div>
            <?php break;

            case 'view_completed_exam': // New page for student to review a previously completed exam
                if (!is_role('student')) { redirect('exam.php'); }

                $student_exam_id = (int)($_GET['student_exam_id'] ?? 0);
                $student_id = $_SESSION['user_id'];

                if ($student_exam_id <= 0) {
                    set_message("Invalid completed exam selection.", "error");
                    redirect('exam.php?page=view_scores');
                }

                // Fetch student_exam details and associated exam details
                $stmt_se_details = $conn->prepare("
                    SELECT se.exam_id, se.score, e.title, e.description
                    FROM student_exams se
                    JOIN exams e ON se.exam_id = e.id
                    WHERE se.id = ? AND se.student_id = ? AND se.completed = 1
                ");
                $stmt_se_details->bind_param("ii", $student_exam_id, $student_id);
                $stmt_se_details->execute();
                $se_result = $stmt_se_details->get_result();
                $student_exam_details = $se_result->fetch_assoc();
                $stmt_se_details->close();

                if (!$student_exam_details) {
                    set_message("Completed exam not found or you don't have permission to view it.", "error");
                    redirect('exam.php?page=view_scores');
                }

                $exam_id = $student_exam_details['exam_id'];
                $exam_title = htmlspecialchars($student_exam_details['title']);
                $exam_description = htmlspecialchars($student_exam_details['description']);
                $student_score = round($student_exam_details['score'], 2);

                // Fetch all questions for this exam
                $questions = [];
                $stmt_questions = $conn->prepare("SELECT id, question_text, question_type FROM questions WHERE exam_id = ? ORDER BY id ASC");
                $stmt_questions->bind_param("i", $exam_id);
                $stmt_questions->execute();
                $questions_result = $stmt_questions->get_result();

                // Fetch all answers (options) and their correctness for this exam
                $all_answers = []; // question_id => [answer_id => {answer_text, is_correct}]
                $stmt_all_answers = $conn->prepare("SELECT a.question_id, a.id AS answer_id, a.answer_text, a.is_correct
                                                    FROM answers a JOIN questions q ON a.question_id = q.id
                                                    WHERE q.exam_id = ?");
                $stmt_all_answers->bind_param("i", $exam_id);
                $stmt_all_answers->execute();
                $all_answers_result = $stmt_all_answers->get_result();
                while ($row = $all_answers_result->fetch_assoc()) {
                    $all_answers[$row['question_id']][$row['answer_id']] = [
                        'answer_text' => $row['answer_text'],
                        'is_correct' => (bool)$row['is_correct']
                    ];
                }
                $stmt_all_answers->close();

                // Fetch student's submitted answers for this specific student_exam_id
                $student_submitted_answers = []; // question_id => {chosen_answer_id, short_answer_text}
                $stmt_student_answers = $conn->prepare("SELECT question_id, chosen_answer_id, short_answer_text FROM student_answers WHERE student_exam_id = ?");
                $stmt_student_answers->bind_param("i", $student_exam_id);
                $stmt_student_answers->execute();
                $student_answers_result = $stmt_student_answers->get_result();
                while ($row = $student_answers_result->fetch_assoc()) {
                    $student_submitted_answers[$row['question_id']] = [
                        'chosen_answer_id' => $row['chosen_answer_id'],
                        'short_answer_text' => $row['short_answer_text']
                    ];
                }
                $stmt_student_answers->close();
                ?>

                <div class="max-w-4xl mx-auto bg-white p-8 rounded-lg shadow-xl border border-gray-200">
                    <h2 class="text-3xl font-bold text-gray-800 mb-4 text-center">Review: <?php echo $exam_title; ?></h2>
                    <p class="text-gray-600 text-center mb-6"><?php echo $exam_description; ?></p>
                    <p class="text-xl font-bold text-center mb-8 <?php echo ($student_score >= 70) ? 'text-green-600' : 'text-red-600'; ?>">
                        Your Score: <?php echo $student_score; ?>%
                    </p>

                    <div class="space-y-8">
                        <?php while ($q = $questions_result->fetch_assoc()):
                            $question_id = $q['id'];
                            $student_answer = $student_submitted_answers[$question_id] ?? ['chosen_answer_id' => null, 'short_answer_text' => null];
                            $chosen_answer_id = $student_answer['chosen_answer_id'];
                            $short_answer_text = htmlspecialchars($student_answer['short_answer_text'] ?? '');
                            $is_question_correct = false; // For MC/TF only
                        ?>
                            <div class="bg-gray-50 p-6 rounded-lg border border-gray-200 shadow-sm">
                                <h4 class="text-xl font-semibold text-gray-800 mb-4">Question:</h4>
                                <p class="text-gray-700 text-lg mb-4"><?php echo htmlspecialchars($q['question_text']); ?></p>

                                <?php if ($q['question_type'] === 'multiple_choice' || $q['question_type'] === 'true_false'): ?>
                                    <div class="space-y-3">
                                        <?php
                                        $correct_options_for_q = [];
                                        if (isset($all_answers[$question_id])) {
                                            foreach ($all_answers[$question_id] as $ans_id => $ans_data) {
                                                if ($ans_data['is_correct']) {
                                                    $correct_options_for_q[] = $ans_id;
                                                }
                                            }
                                        }

                                        if (in_array($chosen_answer_id, $correct_options_for_q)) {
                                            $is_question_correct = true;
                                        }

                                        if (isset($all_answers[$question_id])) {
                                            foreach ($all_answers[$question_id] as $ans_id => $ans_data):
                                                $answer_text = htmlspecialchars($ans_data['answer_text']);
                                                $is_chosen = ($ans_id == $chosen_answer_id);
                                                $is_correct_option = $ans_data['is_correct'];

                                                $class = 'bg-white border-gray-300';
                                                $icon = '';

                                                if ($is_chosen && $is_correct_option) {
                                                    $class = 'bg-green-100 border-green-500';
                                                    $icon = '<i class="fas fa-check-circle text-green-600 ml-2"></i> Your Correct Answer';
                                                } elseif ($is_chosen && !$is_correct_option) {
                                                    $class = 'bg-red-100 border-red-500';
                                                    $icon = '<i class="fas fa-times-circle text-red-600 ml-2"></i> Your Incorrect Answer';
                                                } elseif (!$is_chosen && $is_correct_option) {
                                                    // This is a correct answer that the student did NOT choose
                                                    $class = 'bg-green-50 border-green-300'; // Slightly different green for correct but unchosen
                                                    $icon = '<i class="fas fa-check-circle text-green-500 ml-2"></i> Correct Answer';
                                                }
                                        ?>
                                                <div class="flex items-center p-3 rounded-lg border <?php echo $class; ?>">
                                                    <input type="radio" <?php echo $is_chosen ? 'checked' : ''; ?> disabled
                                                           class="form-radio h-5 w-5 <?php echo $is_chosen ? ($is_correct_option ? 'text-green-600' : 'text-red-600') : 'text-gray-400'; ?>">
                                                    <span class="ml-3 text-gray-800 text-md"><?php echo $answer_text; ?></span>
                                                    <?php echo $icon; ?>
                                                </div>
                                            <?php endforeach;
                                        } ?>
                                    </div>
                                <?php elseif ($q['question_type'] === 'short_answer'): ?>
                                    <div class="bg-gray-100 p-4 rounded-lg border border-gray-200">
                                        <h5 class="text-md font-semibold text-gray-700 mb-2">Your Answer:</h5>
                                        <p class="text-gray-800 whitespace-pre-wrap"><?php echo !empty($short_answer_text) ? $short_answer_text : 'No answer provided.'; ?></p>
                                        <p class="text-sm text-gray-600 italic mt-2">
                                            (Short answer questions require manual grading by the teacher. This score is based on auto-graded questions only.)
                                        </p>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endwhile; ?>
                    </div>

                    <div class="mt-8 text-center">
                        <a href="exam.php?page=view_scores" class="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg shadow-md transition-all duration-300 transform hover:scale-105">
                            <i class="fas fa-arrow-left mr-2"></i>Back to My Scores
                        </a>
                    </div>
                </div>
            <?php break;

            default:
                // Default home page if logged in but no specific page is requested
                if (is_logged_in()) {
                    if (is_role('teacher')) {
                        redirect('exam.php?page=teacher_dashboard');
                    } else {
                        redirect('exam.php?page=student_dashboard');
                    }
                } else { ?>
                    <div class="text-center py-20 px-4 bg-white rounded-lg shadow-xl border border-gray-200">
                        <h1 class="text-5xl font-extrabold text-gray-900 mb-6 leading-tight">
                            Welcome to the <span class="text-indigo-600">Online Exam Platform</span>!
                        </h1>
                        <p class="text-xl text-gray-700 mb-8 max-w-2xl mx-auto">
                            Your comprehensive solution for creating, managing, and taking online exams.
                            Teachers can easily build tests, while students can take them and view their scores.
                        </p>
                        <div class="space-x-4">
                            <a href="exam.php?page=login"
                               class="inline-flex items-center bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-8 rounded-lg shadow-lg transition-all duration-300 transform hover:scale-105 text-lg">
                                <i class="fas fa-sign-in-alt mr-2"></i>Get Started (Login)
                            </a>
                            <a href="exam.php?page=signup"
                               class="inline-flex items-center bg-teal-600 hover:bg-teal-700 text-white font-bold py-3 px-8 rounded-lg shadow-lg transition-all duration-300 transform hover:scale-105 text-lg">
                                <i class="fas fa-user-plus mr-2"></i>Create Account
                            </a>
                        </div>
                    </div>
                <?php }
            break;
        }
        ?>
    </main>

    <footer class="bg-gray-800 text-gray-300 py-6 mt-10 shadow-inner">
        <div class="container mx-auto text-center text-sm">
            <p>&copy; <?php echo date('Y'); ?> Online Exam Platform. All rights reserved.</p>
            <p class="mt-2">Built with <span class="text-red-500">&hearts;</span> using PHP, MySQL, Tailwind CSS, and Font Awesome.</p>
        </div>
    </footer>
</body>
</html>
<?php
// Close the database connection at the end of the script execution
mysqli_close($conn);
?>
