const typescript = require("@rollup/plugin-typescript");

module.exports = {
	input: "src/index.ts",
	external: ["buffer", "crypto"],
	plugins: [
		typescript({
			tsconfig: "./tsconfig.json",
			compilerOptions: {
				declaration: false,
				module: "ESNext",
			},
		}),
	],
	output: [
		{
			file: "dist/index.cjs",
			format: "cjs",
			exports: "default",
		},
		{
			file: "dist/index.mjs",
			format: "esm",
		},
	],
};
