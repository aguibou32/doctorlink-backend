import * as yup from "yup" 
import i18next from "i18next" 

const verifyEmailSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired')),
  token: yup.string()
  .required(() => i18next.t('tokenRequired'))
})

export default verifyEmailSchema