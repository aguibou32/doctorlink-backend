const notFound = (req, res, next) => {
  // Create a new error object with a message indicating the requested URL was not found
  const error = new Error('Not Found - ' + req.originalUrl);
  
  // Set the response status to 404 (Not Found) and send a JSON response with a custom message and the error message
  res.status(404).json({
    message: 'Items Not Found',
    error: error.message
  });
  
  // Pass the error to the next middleware function
  next(error); // Basically saying go to the next error, if there is any in line.
}


const errorHandler = (err, req, res, next) => {
  // Define a variable to hold the status code
  let statusCode;

  // If the response status code is 200 (OK), set it to 500 (Internal Server Error)
  if (res.statusCode === 200) {
    statusCode = 500;
  } else {
    // Otherwise, use the existing response status code
    statusCode = res.statusCode;
  }

  // Define a variable to hold the error message
  let message = err.message;

  // Set the response status to the determined status code
  res.status(statusCode).json({
    message: message,
    // If the environment is production, send a simple message, otherwise send the stack trace
    stack: process.env.NODE_ENV === 'production' ? '🥚' : err.stack
  });
};


export {notFound, errorHandler}