<?php
// Registers (or updates) UniGame Hub as an LTI 1.3 External Tool in a Moodle 4.5 site.
// Usage (from the Moodle root):
//   php <path>/register_tool.php --hub=http://localhost:8787 --pem=<public-key.pem> [--name="UniGame Hub"] [--keyset]
// --keyset: use the Hub's JWKS URL instead of pasting the RSA key (needs Moodle to reach the Hub over HTTP,
//           i.e. not blocked by "cURL blocked hosts"; use it for staging/production).
// Prints JSON with the values to register on the Hub side (issuer, client id, deployment id, endpoints).

define('CLI_SCRIPT', true);
require(getcwd() . '/config.php');
require_once($CFG->libdir . '/clilib.php');
require_once($CFG->dirroot . '/mod/lti/locallib.php');

[$options] = cli_get_params(['hub' => null, 'pem' => null, 'name' => 'UniGame Hub', 'keyset' => false], []);
if (empty($options['hub'])) {
    cli_error('--hub is required');
}
$hub = rtrim($options['hub'], '/');
if (!$options['keyset'] && (empty($options['pem']) || !is_readable($options['pem']))) {
    cli_error('--pem is required (or use --keyset)');
}

\core\session\manager::set_user(get_admin());

$config = new stdClass();
$config->lti_typename = $options['name'];
$config->lti_toolurl = $hub . '/lti/launch';
$config->lti_description = 'Kho game học tập (VSTEP, ClassInteract, CaseStudyHub, Smartwatch, OralExam...). Đăng nhập một lần, điểm tự đồng bộ.';
$config->lti_ltiversion = LTI_VERSION_1P3;
if ($options['keyset']) {
    $config->lti_keytype = LTI_JWK_KEYSET;
    $config->lti_publickeyset = $hub . '/lti/jwks';
} else {
    $config->lti_keytype = LTI_RSA_KEY;
    $config->lti_publickey = trim(file_get_contents($options['pem']));
}
$config->lti_initiatelogin = $hub . '/lti/login';
$config->lti_redirectionuris = $hub . '/lti/launch';
$config->lti_customparameters = '';
$config->lti_coursevisible = LTI_COURSEVISIBLE_ACTIVITYCHOOSER;
$config->lti_launchcontainer = LTI_LAUNCH_CONTAINER_WINDOW;
$config->lti_contentitem = 1;
$config->lti_toolurl_ContentItemSelectionRequest = $hub . '/lti/launch';
$config->lti_sendname = LTI_SETTING_ALWAYS;
$config->lti_sendemailaddr = LTI_SETTING_ALWAYS;
$config->lti_acceptgrades = LTI_SETTING_ALWAYS;
$config->lti_forcessl = 0;
$config->lti_organizationid_default = LTI_DEFAULT_ORGID_SITEID;
$config->lti_organizationid = '';
$config->lti_organizationurl = '';
$config->lti_coursecategories = '';
$config->ltiservice_gradesynchronization = 2; // Use this service for grade sync and column management.
$config->ltiservice_memberships = 1;
$config->ltiservice_toolsettings = 0;

$existing = $DB->get_record('lti_types', ['name' => $options['name'], 'ltiversion' => LTI_VERSION_1P3, 'course' => SITEID]);
if ($existing) {
    $type = new stdClass();
    $type->id = $existing->id;
    $type->state = LTI_TOOL_STATE_CONFIGURED;
    $type->clientid = $existing->clientid;
    lti_update_type($type, $config);
    $typeid = $existing->id;
    $clientid = $existing->clientid;
    $action = 'updated';
} else {
    $type = new stdClass();
    $type->state = LTI_TOOL_STATE_CONFIGURED;
    $typeid = lti_add_type($type, $config);
    $clientid = $DB->get_field('lti_types', 'clientid', ['id' => $typeid]);
    $action = 'created';
}

echo json_encode([
    'action' => $action,
    'typeId' => (int)$typeid,
    'name' => $options['name'],
    'issuer' => $CFG->wwwroot,
    'clientId' => $clientid,
    'deploymentIds' => [(string)$typeid],
    'authUrl' => $CFG->wwwroot . '/mod/lti/auth.php',
    'tokenUrl' => $CFG->wwwroot . '/mod/lti/token.php',
    'jwksUrl' => $CFG->wwwroot . '/mod/lti/certs.php',
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
