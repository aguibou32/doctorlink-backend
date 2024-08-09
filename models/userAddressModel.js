import mongoose from "mongoose"

// Define the address schema
const userAddressSchema = new mongoose.Schema({
  street: {
    type: String,
    required: true
  },
  city: {
    type: String,
    required: true
  },
  state: {
    type: String,
    required: true
  },
  postalCode: {
    type: String,
    required: true
  },
  country: {
    type: String,
    required: true
  }
}, 
{ timestamps: true }
)

// Create the address model
const UserAddressModel = mongoose.model("UserAddressModel", userAddressSchema)

export default UserAddressModel
