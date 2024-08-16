
# 🛠️ EudesBack

Welcome to **EudesBack**, the backend service for **EudesCMS**, built using Node.js. This backend handles the core functionalities of the CMS designed for Habbo retros, including user authentication, file storage, and more.

## 📦 Key Features

- **Authentication & Authorization**: Secure user authentication using JWT and bcrypt.
- **File Storage**: Integration with AWS S3 for file storage, including image uploads via Multer.
- **2FA Support**: Two-Factor Authentication with `node-2fa` and QR code generation.
- **Real-time Communication**: Powered by Socket.io for real-time interactions.
- **Stripe Integration**: Manage payments and subscriptions using Stripe.

## 🚀 Getting Started

To set up the project locally, follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/EudesBack.git
cd EudesBack
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Environment Variables

Create a `.env` file at the root of the project and configure the following environment variables:

```env
PORT=3000
JWT_SECRET=your_jwt_secret
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
STRIPE_SECRET_KEY=your_stripe_secret_key
```

### 4. Start the Development Server

To start the server in development mode with hot reloading:

```bash
npm run dev
```

The server should now be running on `http://localhost:3000`.

## 🧰 Dependencies

EudesBack uses several essential Node.js packages, including:

- **express**: Web framework for building the server.
- **jsonwebtoken**: For secure authentication using JWT tokens.
- **aws-sdk & @aws-sdk/client-s3**: For interacting with AWS S3.
- **mysql2**: Database client for MySQL.
- **socket.io**: Real-time bidirectional communication.
- **stripe**: Integration for payment processing.

…and more! Check the `package.json` for the complete list of dependencies.

## 🧑‍💻 Contributing

Currently, we are not looking for contributors as the project is maintained by **notaryz** and **yourself**. However, you can follow the project to stay updated on future developments.

## 📄 License

This project is licensed under the ISC License. See the [LICENSE](LICENSE) file for more details.

---

Made with ❤️ by the EudesCMS Team

---

Enjoy working with EudesBack! If you have any questions or need further assistance, don't hesitate to reach out. 🌟
