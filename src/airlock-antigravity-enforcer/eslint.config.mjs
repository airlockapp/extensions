// @ts-check
import eslint from "eslint";
import tseslint from "typescript-eslint";

export default tseslint.config(
    { ignores: ["out", "dist", "**/*.d.ts"] },
    {
        files: ["src/**/*.ts"],
        extends: [tseslint.configs.recommended],
        rules: {
            "@typescript-eslint/naming-convention": [
                "warn",
                { selector: "import", format: ["camelCase", "PascalCase"] },
            ],
            semi: "warn",
            curly: "warn",
            eqeqeq: "warn",
        },
    }
);
