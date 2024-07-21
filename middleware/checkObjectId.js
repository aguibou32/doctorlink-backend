import { isValidObjectId } from 'mongoose'

function checkObjectId(req, res, next) {
  if (!isValidObjectId(req.params.id)) {
    res.status(404)
    throw new Error(`Invalid objectId of: ${req.paramsid}`)
  }
}

export default checkObjectId