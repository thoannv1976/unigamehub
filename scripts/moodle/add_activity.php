<?php
// DEV helper: adds a UniGame Hub activity to a course without the Deep Linking dialog.
// Usage (Moodle root): php add_activity.php --course=4 --typeid=3 --game=demo [--activity=round-2] [--name=".."] [--max=100] [--section=2]
define('CLI_SCRIPT', true);
require(getcwd() . '/config.php');
require_once($CFG->libdir . '/clilib.php');
require_once($CFG->dirroot . '/course/modlib.php');
require_once($CFG->dirroot . '/mod/lti/locallib.php');

[$o] = cli_get_params(['course' => null, 'typeid' => null, 'game' => null, 'activity' => '', 'name' => null, 'max' => 100, 'section' => 1, 'policy' => 'latest'], []);
foreach (['course', 'typeid', 'game'] as $k) {
    if (empty($o[$k])) {
        cli_error("--$k is required");
    }
}
\core\session\manager::set_user(get_admin());
$course = get_course((int)$o['course']);
$custom = "game_id={$o['game']}\n" . ($o['activity'] ? "activity={$o['activity']}\n" : '') . "grade_policy={$o['policy']}";

$mi = new stdClass();
$mi->modulename = 'lti';
$mi->module = $DB->get_field('modules', 'id', ['name' => 'lti']);
$mi->course = $course->id;
$mi->section = (int)$o['section'];
$mi->visible = 1;
$mi->name = $o['name'] ?? ('UniGame – ' . $o['game'] . ($o['activity'] ? ' – ' . $o['activity'] : ''));
$mi->intro = '';
$mi->introformat = FORMAT_HTML;
$mi->typeid = (int)$o['typeid'];
$mi->toolurl = '';
$mi->securetoolurl = '';
$mi->instructorcustomparameters = $custom;
$mi->launchcontainer = LTI_LAUNCH_CONTAINER_WINDOW;
$mi->instructorchoicesendname = 1;
$mi->instructorchoicesendemailaddr = 1;
$mi->instructorchoiceacceptgrades = 1;
$mi->grade = (int)$o['max'];
$mi->cmidnumber = '';
$mi->showtitlelaunch = 1;
$mi->showdescriptionlaunch = 0;
$res = add_moduleinfo($mi, $course);
echo json_encode(['cmid' => (int)$res->coursemodule, 'launchUrl' => $CFG->wwwroot . '/mod/lti/launch.php?id=' . $res->coursemodule], JSON_UNESCAPED_SLASHES) . "\n";
