import * as yup from "yup" 
import i18next from "i18next" 

const sendEmailChangeVerificationSchema = yup.object().shape({
  newEmail: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired'))
})

export default sendEmailChangeVerificationSchema