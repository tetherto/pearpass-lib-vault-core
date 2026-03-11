import { eslintConfig } from 'tether-dev-docs'

export default [
  {
    ignores: ['dist', 'src/worklet/app.cjs']
  },
  ...eslintConfig,
  {
    languageOptions: {
      globals: {
        BareKit: 'readonly'
      }
    },
    rules: {
      'no-underscore-dangle': 'off'
    }
  }
]
