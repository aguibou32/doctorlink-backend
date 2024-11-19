import * as yup from "yup" 
import i18next from "i18next" 

const verifyUserSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired')),
  verificationCode: yup
  .string()
  .required(() => i18next.t('tokenRequired'))
  .max(6, () => i18next.t('verificationCodeMaxLength')) 
})

export default verifyUserSchema