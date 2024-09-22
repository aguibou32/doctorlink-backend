import * as yup from "yup" 
import i18next from "i18next" 

const loginSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired')),
  password: yup.string()
  .required(() => i18next.t('passwordRequired')),
  deviceId: yup.string()
  .required(() => i18next.t('deviceIdRequired')),
  deviceName: yup.string()
  .required(() => i18next.t('deviceNameRequired')),
  rememberMe: yup.string()
  .required(() => i18next.t('rememberMeRequired'))
})

export default loginSchema


