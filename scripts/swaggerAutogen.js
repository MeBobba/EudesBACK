const {readdirSync, statSync} = require("fs");
const swaggerAutogen = require('swagger-autogen')({language: 'fr', openapi: '3.0.0'});

const doc = {
    info: {
        title: 'MeBobba API',
        description: 'Documentation pour l\'API de MeBobba',
        version: '1.0'
    },
    servers: [
        {
            url: "http://localhost:3000",
            description: "Local Server"
        },
        {
            url: "https://api.mebobba.com",
            description: "Prod Server"
        }
    ],
    basePath: '/',
    schemes: ['http', 'https'],
    securityDefinitions: {
        bearerAuth: {
            type: 'apiKey',
            name: 'x-access-token',
            in: 'header'
        }
    },
    security: [{ bearerAuth: [] }]
};

const outputFile = '../swagger-output.json';
const routesDir = './routes'; // Directory where route files are located

// Function to get all JavaScript files in a directory
const getFiles = (dir, files_) => {
    files_ = files_ || [];
    const files = readdirSync(dir);
    for (let i in files) {
        const name = dir + '/' + files[i];
        if (statSync(name).isDirectory()) {
            getFiles(name, files_);
        } else if (name.endsWith('.js')) {
            files_.push(name);
        }
    }
    return files_;
};

const endpointsFiles = getFiles(routesDir);

swaggerAutogen(outputFile, endpointsFiles, doc);
