import * as yup from "yup" 
import i18next from "i18next" 
import { isValidPhoneNumber } from 'libphonenumber-js'

const phoneInUseSchema = yup.object().shape({
  phone: yup.string()
  .required(() => i18next.t('phoneRequired'))
  .test('isValidPhoneNumber', () => i18next.t('invalidPhoneNumber'), (value) => isValidPhoneNumber(value)),
})

export default phoneInUseSchema