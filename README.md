# Bonafide International School (BIS) — School Management

A static, front-end-only school management system: public website plus a role-based portal for
administrators, teachers and students. All data lives in the browser (`localStorage`) and can be
exported/imported as a JSON backup, so the system can be moved to another computer (e.g. via USB).

The interface is built with one flat, plain-colour design system — see
[Design](#design). No build step, no framework, and no external network requests.

## How to run

Serve the folder over HTTP — this is the recommended way to run the system:

```bash
cd /home/neg/Projects/2
python3 -m http.server 8000     # or: npx serve .
```

Then open <http://localhost:8000>.

Other options:

- **GitHub Pages:** enable Pages for the repository and use the generated URL (HTTPS, so all
  browser crypto features are available).
- **Opening files directly (`file://`)** works for viewing the public pages, but login needs the
  Web Crypto API. If it is unavailable the login form explains how to fix it. Use HTTP/HTTPS.

## First run — no default passwords

There are **no hard-coded accounts**. On first visit `login.html` switches into a setup screen:

1. Create the first administrator (name, username, password).
2. Optionally tick *Create sample teachers and students* to get demo data.
3. Submitting the form signs you in immediately.

Every account created afterwards (by an administrator) receives a generated temporary password that
is shown **once** in a credentials dialog. That user is forced to choose their own password at first
sign-in, so temporary passwords are never reused.

To start over: administrators can wipe all local data from **Settings → Danger zone**, or clear the
site data in the browser.

## Features

### Public

- Home, About, Gallery (filterable, with lightbox) and Contact pages.
- Contact page shows the **offline `map.png`** image plus a link to the live Google Maps location —
  no external map embed, so it works without internet.
- Footer links to the school's real Facebook, Telegram and YouTube pages; addresses, phone, email
  and social URLs are editable in **Settings** and used across the site.

### Administrator

- Dashboard with live figures (students, teachers, admins, graded students, average mark, locked
  accounts) and a real audit log of sign-ins and changes.
- **User management:** create **administrators**, teachers and students; search and filter; edit
  details, grade, section, subject, class teacher and status; generate/reset passwords; unlock
  locked accounts; remove accounts. Credentials are copyable; the account list can be exported to
  CSV (without passwords).
- **Announcements:** publish, pin, edit and delete notices per audience (everyone, students,
  teachers, administrators).
- **Timetables:** build a weekly timetable per grade (Monday–Friday) with periods, subjects, rooms
  and teachers.
- **Settings:** school name, tagline, address, phone, email, map image/query, social links, plus
  JSON backup export/import and a data wipe.

### Teacher

- Dashboard: students in assigned grades, today's periods, attendance rate, class average.
- **Attendance register:** per grade and date, with present / late / absent / excused toggles,
  "mark all present", and a recent-days history. Teachers can only record their own grades.
- **Gradebook:** one editable column per subject, per student, with live averages, letter grades
  and class statistics.
- **My timetable:** only the periods assigned to the signed-in teacher.
- Announcements for staff.

### Student

- Dashboard: average mark, letter grade, subjects graded, attendance rate, today's periods.
- **Academic report:** subject marks with comments, personal-development ratings, attendance
  history, and a print/PDF layout.
- **My timetable:** read-only weekly schedule for the student's grade.
- Announcements for students.

## Design

The interface uses one flat, plain-colour design system defined in `css/site.css` and shared by all
21 pages.

- **Plain flat surfaces** — every panel, card, button and badge is a **solid** colour. There are no
  gradients, no transparency, no `backdrop-filter` blur and no inset highlights, so nothing looks
  glossy or "shiny". Depth comes from a single soft shadow, not from shine.
- **One border, not two** — components use a single `1px` border. The earlier hairline-plus-inset
  "double ring" treatment was removed everywhere, so edges read as one clean line.
- **Blue-cyan palette** — the primary colour is sky blue `#0ea5e9` with cyan `#06b6d4` as the
  secondary; text is navy `#0b2a4a` on a pale blue `#e8f1f8` background. There is no black, purple
  or pink anywhere. Green, amber and red appear only where they carry meaning: present / success,
  late or warning, and absent or destructive actions.
- **No external dependencies** — the whole site is plain HTML, CSS and JavaScript with **no build
  step, no framework and no CDN or font requests**. Typography uses the platform system stack
  (`-apple-system` / `BlinkMacSystemFont` / `SF Pro Text`), falling back to `Inter`, `Segoe UI` and
  `Roboto`. It renders instantly and works offline.
- **Light only** — a single light appearance, identical on every device and when printed. It does
  not follow the operating system's dark-mode setting.
- **Accessibility and motion** — `prefers-reduced-motion: reduce` disables all transitions; text
  contrast is held above AA.
- **Printing** — a `@media print` block hides navigation, footers and buttons and removes shadows
  and borders, so the report and attendance registers print and save to PDF cleanly.

Page-specific styling is **not** inlined. All page styles (hero, gallery, auth, timetables,
gradebook, report cards, modals, toasts) are part of the shared stylesheet, so a visual change
applies site-wide.

## Project structure

| Path | Purpose |
|------|---------|
| `index.html`, `about.html`, `gallary.html`, `contact-us.html` | Public pages |
| `login.html`, `change_password.html`, `profile.html` | Authentication and self-service |
| `dashboard_admin.html`, `dashboard_teacher.html`, `dashboard_student.html` | Role dashboards |
| `user_management_admin.html` | Accounts, roles and credentials |
| `announcement_admin.html`, `announcements_teacher.html`, `announcements_student.html` | Announcements |
| `timetable_admin.html`, `timetable_teacher.html`, `timetable_student.html` | Timetables |
| `attendance_teacher.html` | Attendance register |
| `reports_academic.html`, `reports_student_teacher_view.html` | Student report, teacher gradebook |
| `settings_admin.html` | School settings, backup, data wipe |
| `css/site.css` | The entire design system: colour tokens, flat components, responsive and print styles |
| `js/bis_store.js` | Data layer: auth, accounts, attendance, grades, timetable, announcements, audit, settings, backup |
| `js/app.js` | Shared shell: header, role navigation, footer with social links, UI helpers |
| `js/<page>.js` | One small controller per page |
| `map.png` | Offline map shown on the contact page |

Page load order is always `js/bis_store.js` → `js/app.js` → the page's own script.

## Security model

- Passwords are hashed with **PBKDF2-SHA256, 310 000 iterations** and a per-account random salt.
  Plaintext passwords are never stored.
- **5 failed sign-ins within 15 minutes locks the account for 15 minutes**; administrators can
  unlock it from user management.
- Sessions live in `sessionStorage`, so closing the browser tab signs the user out. Sessions expire
  after **30 minutes idle** or **4 hours** in total, and are invalidated when the password changes.
- Roles are enforced **in the data layer**, not just hidden in the UI: teachers can only record
  attendance and grades for grades they actually teach, only administrators can create
  administrators, publish announcements or change settings, and the last active administrator
  cannot be removed or demoted.
- All user-supplied text is sanitised before storage and inserted with `textContent`, not
  `innerHTML`, which removes the stored-XSS risk of the previous version.

**Important limitation:** this is a static site with no server. Password hashing and the session
rules above are real, but any data in `localStorage` can be read or edited by whoever has access to
the browser profile, and there is no protection against a user editing their own browser data. That
is acceptable for a small, single-machine deployment — it is **not** a substitute for a
server-backed system if you need real multi-user security or audit-grade records.

## License

Use and modify as needed for your school or portfolio.
