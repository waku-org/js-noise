process.env.CHROME_BIN = require("puppeteer").executablePath();

const os = require("os");
const path = require("path");

const rollupConfig = import("./rollup.config.js");

const output = {
  path: path.join(os.tmpdir(), "_karma_webpack_") + Math.floor(Math.random() * 1000000),
};

module.exports = function (config) {
  config.set({
    frameworks: ["rollup", "mocha"],
    preprocessors: {
      "**/*.ts": ["rollup"],
    },

    files: [
      "src/**/*.spec.ts",
      "src/**/*.ts",
      {
        pattern: `${output.path}/**/*`,
        watched: false,
        included: false,
        served: true,
      },
    ],
    envPreprocessor: ["CI"],
    reporters: ["progress"],
    browsers: ["ChromeHeadless"],
    singleRun: true,
    client: {
      mocha: {
        timeout: 6000, // Default is 2s
      },
    },
    rollupPreprocessor: { ...rollupConfig },
  });
};
