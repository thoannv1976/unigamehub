/** LTI 1.3 / Advantage claim names. */
const P = 'https://purl.imsglobal.org/spec/lti';
export const CLAIM = {
  messageType: `${P}/claim/message_type`,
  version: `${P}/claim/version`,
  deploymentId: `${P}/claim/deployment_id`,
  targetLinkUri: `${P}/claim/target_link_uri`,
  roles: `${P}/claim/roles`,
  context: `${P}/claim/context`,
  resourceLink: `${P}/claim/resource_link`,
  custom: `${P}/claim/custom`,
  launchPresentation: `${P}/claim/launch_presentation`,
  toolPlatform: `${P}/claim/tool_platform`,
  ags: 'https://purl.imsglobal.org/spec/lti-ags/claim/endpoint',
  nrps: 'https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice',
  dlSettings: 'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings',
  dlContentItems: 'https://purl.imsglobal.org/spec/lti-dl/claim/content_items',
  dlData: 'https://purl.imsglobal.org/spec/lti-dl/claim/data',
} as const;

export const SCOPE = {
  score: 'https://purl.imsglobal.org/spec/lti-ags/scope/score',
  lineitem: 'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem',
  resultRead: 'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly',
  nrps: 'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly',
} as const;

export type HubRole = 'instructor' | 'learner';

const INSTRUCTOR_RE =
  /(membership#(Instructor|ContentDeveloper|Administrator|Mentor)$)|(membership\/Instructor#)|(institution\/person#Administrator$)|(system\/person#Administrator$)/;

export function normalizeRole(roles: unknown): HubRole {
  const list = Array.isArray(roles) ? roles.map(String) : [];
  return list.some((r) => INSTRUCTOR_RE.test(r)) ? 'instructor' : 'learner';
}
