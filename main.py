from app.init import create_app

app = create_app() 

if __name__ == "__main__":
    app.run(
        debug=True,
        ssl_context=(
            "/home/csp-ghost-delta-purple/Documents/FASTT/certs/cert.pem", 
            "/home/csp-ghost-delta-purple/Documents/FASTT/certs/key.pem"
        ),
        host="0.0.0.0",
        port=5000
    )