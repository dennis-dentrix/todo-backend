const express = require('express')
const router = express.Router()
const listController = require("../controllers/listController")
const authController = require("../controllers/authController");

router.route('/').post(listController.createItem).get(authController.protect, listController.getAllItems)
router.route('/:id').get(listController.getAnItem).patch(listController.updateItem)
router.route('/:id').delete(listController.deleteItem)

module.exports = router;