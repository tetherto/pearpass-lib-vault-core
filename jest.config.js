export default {
  transform: {
    '^.+\\.[jt]sx?$': 'babel-jest'
  },
  transformIgnorePatterns: [
    'node_modules/(?!(bare-crypto|expo-asset|pear-apps-utils-validator|otpauth)/)'
  ],
  setupFiles: ['<rootDir>/jest.setup.js']
}
