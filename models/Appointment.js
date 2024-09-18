const mongoose = require('mongoose');

const AppointmentSchema = new mongoose.Schema({
    
    collectorUserId: {
        type: String,
        required: true
    },
    collectorName: {
        type: String,
        required: true
    },
    collectorContact: {
        type: Number,
        required: true,
    },

    collectorEmail: {
        type: String,
        required: true,
    },
   
    collectorAddress: {
        type: String,
        required: true
    },
    donorUserId: {
        type: String,
        required: true
    },
    donorName: { 
        type: String,
        required: true
    },
    donorEmail: {
        type: String,
        required: true
    },
    

}, { timestamps: true }); // Adiciona timestamps para 'createdAt' e 'updatedAt'

const Appointment = mongoose.model('Appointment', AppointmentSchema);

module.exports = Appointment;
