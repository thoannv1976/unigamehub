<?php
// DEV ONLY. Creates a test course with one teacher and two students for UniGame Hub testing.
// Usage (from the Moodle root): php <path>/seed_test_course.php --out=<file.json>
// Passwords are random and written only to --out (keep that file out of Git).

define('CLI_SCRIPT', true);
require(getcwd() . '/config.php');
require_once($CFG->libdir . '/clilib.php');
require_once($CFG->dirroot . '/course/lib.php');
require_once($CFG->dirroot . '/user/lib.php');
require_once($CFG->libdir . '/enrollib.php');

[$options] = cli_get_params(['out' => null], []);
if (empty($options['out'])) {
    cli_error('--out is required');
}
if (!empty($CFG->wwwroot) && !preg_match('#^https?://(localhost|127\.0\.0\.1)(:\d+)?(/|$)#', $CFG->wwwroot)) {
    cli_error('Refusing to seed test data on a non-local site: ' . $CFG->wwwroot);
}
\core\session\manager::set_user(get_admin());

$course = $DB->get_record('course', ['shortname' => 'GAMEHUB-TEST']);
if (!$course) {
    $data = new stdClass();
    $data->fullname = 'UniGame Hub – Khóa kiểm thử';
    $data->shortname = 'GAMEHUB-TEST';
    $data->category = $DB->get_field_select('course_categories', 'MIN(id)', '1=1');
    $data->summary = 'Khóa học dùng để kiểm thử tích hợp UniGame Hub (LTI 1.3).';
    $data->format = 'topics';
    $data->numsections = 2;
    $course = create_course($data);
}

$genpass = function(): string {
    return 'Gh!' . substr(bin2hex(random_bytes(6)), 0, 10) . 'A9';
};
$people = [
    ['gh_teacher', 'Giảng viên', 'Kiểm thử', 'editingteacher'],
    ['gh_student1', 'Sinh viên', 'Một', 'student'],
    ['gh_student2', 'Sinh viên', 'Hai', 'student'],
];
$out = ['courseId' => (int)$course->id, 'courseUrl' => $CFG->wwwroot . '/course/view.php?id=' . $course->id, 'users' => []];
$manual = enrol_get_plugin('manual');
$instance = $DB->get_record('enrol', ['courseid' => $course->id, 'enrol' => 'manual']);
foreach ($people as [$username, $first, $last, $role]) {
    $pass = $genpass();
    $user = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id]);
    if (!$user) {
        $id = user_create_user((object)[
            'username' => $username, 'password' => $pass, 'firstname' => $first, 'lastname' => $last,
            'email' => $username . '@gamehub.test', 'auth' => 'manual', 'confirmed' => 1,
            'mnethostid' => $CFG->mnet_localhost_id, 'lang' => 'vi',
        ], true, false);
        $user = $DB->get_record('user', ['id' => $id]);
    } else {
        update_internal_user_password($user, $pass);
    }
    $roleid = $DB->get_field('role', 'id', ['shortname' => $role]);
    $manual->enrol_user($instance, $user->id, $roleid);
    $out['users'][] = ['username' => $username, 'password' => $pass, 'role' => $role, 'id' => (int)$user->id];
}
file_put_contents($options['out'], json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
echo "Seeded course {$course->id} ({$out['courseUrl']}) with " . count($out['users']) . " users. Credentials in {$options['out']}\n";
