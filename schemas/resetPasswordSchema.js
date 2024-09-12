import * as yup from "yup"
import i18next from "i18next"

const resetPasswordSchema = yup.object().shape({
  newPassword: yup.string()
    .required(() => i18next.t('passwordRequired'))
    .min(8, () => i18next.t('passwordMinLength')),
  token: yup.string()
    .required(() => i18next.t('tokenRequired'))
})

export default resetPasswordSchema