from app import create_app

app = create_app()

if __name__ == '__main__':
	# debug=False for production; we'll run in dev mode for now
	app.run(host='127.0.0.1', port=5000, debug=True)
