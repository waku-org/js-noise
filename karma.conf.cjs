process.env.CHROME_BIN = require("puppeteer").executablePath();

const os = require("os");
const path = require("path");

const { nodeResolve } = require("@rollup/plugin-node-resolve");
const commonjs = require("@rollup/plugin-commonjs");
const json = require("@rollup/plugin-json");

const rollupConfig = {
  input: {
    index: "dist/index.js",
  },
  output: {
    dir: "bundle",
    format: "esm",
  },
  plugins: [
    commonjs(),
    json(),
    nodeResolve({
      browser: true,
      preferBuiltins: false,
      extensions: [".js", ".ts"],
    }),
  ],
};

const output = {
  path: path.join(os.tmpdir(), "_karma_webpack_") + Math.floor(Math.random() * 1000000),
};

module.exports = function (config) {
  config.set({
    frameworks: ["mocha"],
    preprocessors: {
      "**/*.ts": ["rollup"],
    },

    files: [
      "src/**/*.spec.ts",
      "src/**/*.ts",
      {
        pattern: `${output.path}/**/*`,
        watched: false,
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
