import { eslintConfig } from '@tetherto/tether-dev-docs'

export default [
  {
    ignores: ['dist', 'src/worklet/app.cjs', 'poc']
  },
  ...eslintConfig,
  {
    languageOptions: {
      globals: {
        BareKit: 'readonly',
        Bare: 'readonly'
      }
    },
    rules: {
      'no-underscore-dangle': 'off'
    }
  }
]
