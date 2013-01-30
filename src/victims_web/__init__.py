

if __name__ == '__main__':
    from victims_web.application import app
    # If we are called locally run with debug on
    app.run(debug=True)
