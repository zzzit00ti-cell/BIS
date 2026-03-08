# Bonafide International School (BIS) — School Management

A static, front-end-only school information system: login, announcements, user management, timetables, and academic reports. Data is stored in the browser (localStorage) and can be exported/imported as JSON for backup or moving to another computer (e.g. via USB).

## How to run

- **Option A:** Open `index.html` in a modern browser (Chrome, Firefox, Edge). For full behavior (e.g. secure crypto for passwords), serve over HTTP:
  - From the project folder run: `npx serve .` then open `http://localhost:3000`
  - Or host on **GitHub Pages**: enable Pages for this repo and use the generated URL.
- **Option B:** Open files directly with `file://`. Login and data will work in most browsers; some restrictions may apply.

## Default login

After first load (or after using “Reset all accounts” on the login page), these accounts are available:

| Role   | Username      | Password    |
|--------|---------------|-------------|
| Admin  | `admin`       | `Admin@2026` |
| Teacher| `daniel.math` | `Teacher@2026` |
| Teacher| `eleni.english` | `Teacher@2026` |
| Student| `abebech.10a` | `Student@2026` |
| Student| `chala.10b`   | `Student@2026` |
| Student| `fatuma.11a`  | `Student@2026` |

Admin can create new teachers and students (with optional initial password); otherwise the temporary password is `ChangeMe123`.

## Features

- **Login:** Username/password; roles: Admin, Teacher, Student.
- **Admin:** Dashboard, user management (add/edit/reset password, remove), announcements, export/import data (JSON).
- **Teacher:** Dashboard, announcements, timetable, student academics view with optional “Import from image” (filename-based demo).
- **Student:** Dashboard, announcements, timetable, academic reports.
- **Data portability:** Export and import full data (accounts + announcements) as a JSON file so the system works on another PC or after moving the folder (e.g. via USB).

## Project structure

- `index.html`, `about.html`, `gallary.html`, `contact us.html` — public pages.
- `login.html` — login; uses `js/bis_store.js` for auth and data.
- `dashboard_admin.html`, `dashboard_teacher.html`, `dashboard_student.html` — role dashboards.
- `user_management_admin.html` — admin user directory; create users, reset passwords.
- `announcement_admin.html`, `announcements_teacher.html`, `announcements_student.html` — announcements.
- `timetable_teacher.html`, `timetable_student.html` — timetables.
- `reports_academic.html`, `reports_student_teacher_view.html` — academic reports (teacher view has import-from-image demo).
- `js/bis_store.js` — single source of truth: auth, accounts, announcements, export/import.

## Security note

Passwords are hashed (PBKDF2-SHA256) in the browser. This improves safety for a static site but does not replace server-side security; treat as appropriate for a portable, offline-capable demo/small deployment.

## License

Use and modify as needed for your school or portfolio.
