import i18next from 'i18next'
import Backend from 'i18next-fs-backend'
import { join } from 'path'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import middleware from 'i18next-http-middleware'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

i18next
  .use(Backend)
  .use(middleware.LanguageDetector)
  .init({
    fallbackLng: 'fr',
    backend: {
      loadPath: join(__dirname, 'locales', '{{lng}}', '{{ns}}.json'),
    },
    preload: ['fr', 'en'],
    ns: ['translation'],
    defaultNS: 'translation',
    detection: {
      order: ['cookie'],
      lookupCookie: 'language',
      caches: ['cookie'],
    },
    // debug: true,
  })

export default i18next
