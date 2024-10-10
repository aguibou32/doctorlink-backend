import * as yup from "yup" 
import i18next from "i18next" 

const verifyTwoFactorSchema = yup.object().shape({
  email: yup.string()
  .email(() => i18next.t('emailInvalid'))
  .required(() => i18next.t('emailRequired')),
  twoFactorCode: yup.string()
  .required(() => i18next.t('twoFactorCodeRquired')),
  deviceId: yup.string()
  .required(() => i18next.t('deviceIdRequired')),
  deviceName: yup.string()
  .required(() => i18next.t('deviceNameRequired'))
})

export default verifyTwoFactorSchema