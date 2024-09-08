import * as yup from "yup" 
import i18next from "i18next" 
import moment from "moment" 
import { isValidPhoneNumber } from 'libphonenumber-js'

const registerSchema = yup.object().shape({
  // Email validation
  email: yup.string()
    .email(() => i18next.t('emailInvalid'))
    .required(() => i18next.t('emailRequired')),

  // Personal details validation
  gender: yup.string()
    .required(() => i18next.t('genderRequired')),
  name: yup.string()
    .required(() => i18next.t('nameRequired'))
    .matches(/^[A-Za-z\s]+$/, () => i18next.t('nameInvalid')), // Only letters and spaces
  surname: yup.string()
    .required(() => i18next.t('surnameRequired'))
    .matches(/^[A-Za-z\s]+$/, () => i18next.t('surnameInvalid')), // Only letters and spaces
  dob: yup.string()
    .required(() => i18next.t('dobRequired'))
    .test(
      'is-valid-dob',
      () => i18next.t('dobInvalid'),
      (value) => value ? moment(value, 'DD/MM/YYYY', true).isValid() : false
    )
    .test(
      'is-reasonable-age',
      () => i18next.t('dobMax'),
      (value) => {
        if (!value) return false 
        const date = moment(value, 'DD/MM/YYYY') 
        return date.isValid() && date.isBefore(moment()) && date.year() > 1900 
      }
    ),

  // Phone number validation
  phone: yup.string()
    .required(() => i18next.t('phoneRequired'))
    .test('isValidPhoneNumber', () => i18next.t('invalidPhoneNumber'), (value) => isValidPhoneNumber(value)),

  // Password validation
  password: yup.string()
    .required(() => i18next.t('passwordRequired'))
    .min(8, () => i18next.t('passwordMinLength')), 
  // confirmPassword: yup.string()
  //   .oneOf([yup.ref('password'), null], () => i18next.t('passwordsMustMatch'))
  //   .required(() => i18next.t('confirmPasswordRequired')),

  // Terms acceptance
  terms: yup.bool()
    .oneOf([true], () => i18next.t('termsMustBeAccepted'))
})

export default registerSchema