import * as yup from "yup" 
import i18next from "i18next" 
import { isValidPhoneNumber } from 'libphonenumber-js'

const sendVerificationCodeByEmailSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired'))
})

export default sendVerificationCodeByEmailSchema