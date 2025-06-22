# Online Exam Platform

[![GitHub Workflow Status](https://img.shields.io/badge/status-active-success)](https://github.com/your-username/your-repo-name)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Hosted on Example](https://img.shields.io/badge/hosted%20on-example.com-orange)](http://example.com/your-app-url)

A comprehensive web-based application built with PHP, MySQL, and modern frontend technologies, designed to facilitate online examinations for both teachers and students. This platform enables teachers to create and manage exams, while students can take these exams and review their performance with automatic grading.

## ✨ Features

* **User Authentication:** Secure login, signup, and logout functionality for both teachers and students.

* **Role-Based Access:**

    * **Teachers:** Create new exams, define questions (Multiple Choice, True/False, Short Answer), set correct answers (marking scheme), and view student performance.

    * **Students:** Browse available exams, take timed exams, and review their previously completed exams with detailed feedback on correct/incorrect answers.

* **Dynamic Exam Creation:** Teachers can add multiple questions of various types dynamically via the intuitive frontend interface.

* **Automatic Grading:** For Multiple Choice and True/False questions, exams are automatically graded upon submission, and scores are provided instantly.

* **Real-time Exam Timer:** Students taking an exam see a live countdown, and the exam auto-submits if time runs out.

* **Performance Tracking:**

    * Teachers can view a summary of all students who took a specific exam, along with their scores.

    * Students can view a list of all their completed exams and revisit individual exams to see their answers marked as correct (green) or incorrect (red), with correct answers highlighted.

* **Responsive and Modern UI:** Styled using Tailwind CSS for a clean, mobile-friendly interface, enhanced with Google Fonts (Inter) and Font Awesome icons.

## 🚀 Technologies Used

* **Backend:** PHP

* **Database:** MySQL

* **Database Connection:** `mysqli` (PHP extension for MySQL)

* **Frontend Styling:** Tailwind CSS v3.x

* **Fonts:** Google Fonts (Inter)

* **Icons:** Font Awesome v6.x

* **Client-side Logic:** Vanilla JavaScript

* **Server Environment:** XAMPP, LAMP, WAMP (or any compatible Apache/Nginx with PHP)

<details>
<summary><h2>📦 Setup Instructions</h2></summary>

Follow these steps to get the project up and running on your local machine.

### Prerequisites

* A web server with PHP (e.g., Apache, Nginx)

* MySQL database server

* PHP 7.4 or higher (for `password_hash` and modern PHP features)

### 1. Database Setup

First, create your database and tables.

1.  **Create Database:**
    Open your MySQL client (e.g., phpMyAdmin, MySQL Workbench, or command line) and create a new database.

    ```sql
    CREATE DATABASE exam_db;
    ```

    * **Important:** Ensure the database name matches what's defined in your `connect.php` file (`define('DB_NAME', 'exam_db');`).

2.  **Create Tables:**
    Switch to the newly created database and run the following SQL queries to set up the necessary tables:

    ```sql
    USE exam_db; -- Use the database you just created

    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('teacher', 'student') NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE exams (
        id INT AUTO_INCREMENT PRIMARY KEY,
        teacher_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        duration_minutes INT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE questions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        exam_id INT NOT NULL,
        question_text TEXT NOT NULL,
        question_type ENUM('multiple_choice', 'true_false', 'short_answer') NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
    );

    CREATE TABLE answers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        question_id INT NOT NULL,
        answer_text TEXT NOT NULL,
        is_correct BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
    );

    CREATE TABLE student_exams (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_id INT NOT NULL,
        exam_id INT NOT NULL,
        start_time DATETIME NOT NULL,
        end_time DATETIME,
        score DECIMAL(5,2),
        completed BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
        UNIQUE(student_id, exam_id) -- Ensures a student can only take an exam once (or one active attempt)
    );

    CREATE TABLE student_answers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_exam_id INT NOT NULL,
        question_id INT NOT NULL,
        chosen_answer_id INT, -- For multiple choice/true false
        short_answer_text TEXT, -- For short answer type questions
        FOREIGN KEY (student_exam_id) REFERENCES student_exams(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE,
        FOREIGN KEY (chosen_answer_id) REFERENCES answers(id) ON DELETE CASCADE
    );
    ```

### 2. Project Files

1.  **Clone the Repository (or download files):**

    ```bash
    git clone <your-repository-url>
    cd online-exam-platform
    ```

    If you've downloaded the files directly, ensure they are placed in your web server's document root (e.g., `C:\xampp\htdocs\online-exam-platform` for XAMPP).

2.  **Configure `connect.php`:**
    Open the `connect.php` file and update the database credentials to match your MySQL setup.

    ```php
    <?php
    define('DB_SERVER', 'localhost'); // e.g., 'localhost'
    define('DB_USERNAME', 'root');    // e.g., 'root'
    define('DB_PASSWORD', '');        // e.g., '' (empty for XAMPP root without password)
    define('DB_NAME', 'exam_db'); // Must match the database name you created
    // ... rest of the file
    ?>
    ```

### 3. Run the Application

* Start your web server (e.g., Apache via XAMPP control panel).

* Open your web browser and navigate to the project's URL. For example:

    `http://localhost/online-exam-platform/exam.php`

    (Adjust the path if your project directory name is different).
</details>

## 💡 Usage

### For New Users:

1.  **Sign Up:** Click the "Sign Up" button. Choose your desired role (`Student` or `Teacher`) and create an account.

2.  **Log In:** Use your newly created credentials to log in.

### For Teachers:

1.  After logging in, you'll be directed to the **Teacher Dashboard**.

2.  **Create Exam:** Click the "Create New Exam" button.

    * Fill in the exam title, description, and duration.

    * **Add Questions:** Click "Add Question" to add new questions.

        * Enter the question text.

        * Select the question type:

            * **Multiple Choice / True/False:** Add answer options using "Add Option". For each option, check the radio button next to the text field to mark it as the **correct answer**. This creates your automatic **marking scheme**.

            * **Short Answer:** No options are needed here; students will type their answers. These questions are *not* automatically graded by the system.

    * Click "Create Exam" to save the exam.

3.  **View Results:** On the Teacher Dashboard, click "View Results" next to an exam to see a list of students who have taken it and their scores.

4.  **Delete Exam:** You can also delete exams from the dashboard.

### For Students:

1.  After logging in, you'll be directed to the **Student Dashboard**.

2.  **Available Exams:** This section lists exams you haven't completed or are currently in progress.

    * Click "Take Exam" to start an exam.

    * Pay attention to the countdown timer. The exam will automatically submit when time runs out.

3.  **My Scores:** This section lists all exams you have previously completed.

    * Click "View Details" next to a completed exam to review your performance.

    * **Reviewing Answers:** For Multiple Choice and True/False questions, your chosen answer will be highlighted. If it was correct, it will be in green. If incorrect, your answer will be in red, and the correct answer will also be shown in green. Short answers will display your input without correctness feedback.

## 🤝 Contributing

Feel free to fork this repository, open issues, or submit pull requests to improve the platform!

## 📄 License

This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file for details. You are free to use, modify, and distribute this software, provided derivative works are also licensed under the GNU GPL v3. The source code must be made available when distributing the software.
