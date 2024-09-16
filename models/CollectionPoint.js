const mongoose = require('mongoose');

const CollectionPointSchema = new mongoose.Schema({
    
    userId: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    contact: {
        type: Number,
        required: true,
    },

    email: {
        type: String,
        required: true,
    },
   
    address: {
        type: String,
        required: true
    },
    material: {
        type: String,
        required: true
    }

}, { timestamps: true }); // Adiciona timestamps para 'createdAt' e 'updatedAt'

const CollectionPoint = mongoose.model('CollectionPoint', CollectionPointSchema);

module.exports = CollectionPoint;
