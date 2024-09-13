import * as yup from "yup"
import i18next from "i18next" 

 const changePasswordSchema = yup.object().shape({
  currentPassword: yup.string().required(() => i18next.t('currentPasswordRequired')),
  newPassword: yup.string()
  .required(() => i18next.t('newPasswordRequired'))
  .min(8, () => i18next.t('passwordMinLength'))
})       

export default changePasswordSchema