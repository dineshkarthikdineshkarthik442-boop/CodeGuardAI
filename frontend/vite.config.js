import {defineConfig} from 'vite';
export default defineConfig({base:process.env.CODEGUARD_DOCKER_BUILD==='1'?'/app/':'/'});
