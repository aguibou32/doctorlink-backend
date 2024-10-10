import * as yup from "yup" 
import i18next from "i18next" 

const resend2FACodeSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired'))
})

export default resend2FACodeSchema