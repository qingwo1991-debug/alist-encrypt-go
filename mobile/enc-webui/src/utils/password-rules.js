export const createPasswordRule = (overrides = {}) => ({
  id: Math.random(),
  encType: 'aesctr',
  encName: false,
  encSuffix: '',
  describe: '',
  encPath: '',
  ...overrides,
  password: '',
  enable: false
})

export const hasEnabledRuleWithoutPassword = (rules = []) => {
  return rules.some((rule) => rule?.enable && !String(rule.password ?? '').trim())
}
