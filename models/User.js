const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['donor', 'collector'],  // Define que o usuário pode ser doador ou coletor
        required: true
    },
    collectionPoints: [
        {
            name: String,
            contact: String,
            email: String,
            address: String,
            material: String
        }
    ]
}, { timestamps: true }); // Adiciona timestamps para 'createdAt' e 'updatedAt'

const User = mongoose.model('User', UserSchema);

module.exports = User;
