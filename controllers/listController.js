const List = require('../models/listModel');


exports.createItem = async (req, res) => {
  try {
    const newItem = await List.create(req.body)
  // console.log(newItem)

  res.status(201).json({
    status: "success",
    data: {
      item: newItem
    }
  })

  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    })
    
  }
}

exports.getAllItems = async(req, res)=>{
  try {
    const list = await List.find()
    // console.log(list)

    res.status(200).json({
      status: "success",
      results: list.length,
      data: {
        list
      }
    })
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    }) 
  }
}

exports.getAnItem = async(req, res) => {
  try {
    const item = await List.findById(req.params.id)

    res.status(200).json({
      status: "success",
      data: {
        item
      }
    })
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    })
  }
}

exports.updateItem = async(req, res) => {
  try {
    const item = await List.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    });
  
    res.status(200).json({
      status: 'success',
      data: {
        item
      }
    });
  } catch (error) {
    res.status(404).json({
      status: "fail",
      message: error
    })
  }
}


exports.deleteItem = async (req, res) => {
  
  try {
    await List.findByIdAndDelete(req.params.id)
    
    res.status(204).json({
      status: "success",
      data: null
    })
  } catch (error) {
    res.status(400).json({
      status: "fail",
      message: error
    })
  }
}
