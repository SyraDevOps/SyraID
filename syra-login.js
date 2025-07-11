// syra-login.js - Plugin de Autenticação SyraID

class SyraLoginWidget {
    constructor(containerId, apiBaseUrl) {
        this.container = document.getElementById(containerId);
        this.apiBaseUrl = apiBaseUrl;
        this.jwt = null;

        if (!this.container) {
            console.error(`[SyraID] Elemento container com id '${containerId}' não encontrado.`);
            return;
        }

        // Injeta os estilos do widget na página
        this.injectStyles();
        // Verifica se já existe um token salvo
        this.loadTokenFromStorage();
        // Renderiza o estado inicial do widget
        this.render();
    }
    
    // Decodifica o payload do JWT sem verificar a assinatura (apenas para obter dados)
    parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    // Carrega o token do localStorage
    loadTokenFromStorage() {
        const token = localStorage.getItem('syra_jwt');
        if (token) {
            const payload = this.parseJwt(token);
            // Verifica se o token não está expirado
            if (payload && payload.exp * 1000 > Date.now()) {
                this.jwt = token;
                this.username = payload.username;
            } else {
                localStorage.removeItem('syra_jwt'); // Limpa token expirado
            }
        }
    }

    // Renderiza a aparência do widget (logado ou deslogado)
    render() {
        this.container.innerHTML = ''; // Limpa o container
        if (this.jwt) {
            this.renderLoggedInState();
        } else {
            this.renderLoggedOutState();
        }
    }

    renderLoggedOutState() {
        const button = document.createElement('button');
        button.className = 'syra-login-btn';
        button.innerHTML = `
            <svg class="syra-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="20" height="20" fill="currentColor"><path d="M256 0c4.6 0 9.2 1 13.4 2.9L457.7 82.8c22 9.3 38.4 31 38.3 57.2c-.5 99.2-41.3 280.7-213.6 363.2c-16.7 8-36.1 8-52.8 0C57.3 420.7 16.5 239.2 16 140c-.1-26.2 16.3-47.9 38.3-57.2L242.7 2.9C246.8 1 251.4 0 256 0zm0 66.8L108.8 128H403.2L256 66.8zM403.2 192H108.8c-12.2 0-23.1 8.1-26.8 19.8l-16 48c-3.1 9.3-1.6 19.6 4.1 27.2s16.3 11 26.8 11H416c10.4 0 20-3.4 26.8-11s7.2-17.9 4.1-27.2l-16-48C426.3 200.1 415.4 192 403.2 192z"/></svg>
            <span>Logar com SyraID</span>
        `;
        button.addEventListener('click', () => this.showLoginModal());
        this.container.appendChild(button);
    }

    renderLoggedInState() {
        const loggedInContainer = document.createElement('div');
        loggedInContainer.className = 'syra-logged-in-container';
        loggedInContainer.innerHTML = `
            <p class="syra-welcome-text">Logado como: <strong>${this.username}</strong></p>
            <button class="syra-logout-btn">Sair</button>
        `;
        loggedInContainer.querySelector('.syra-logout-btn').addEventListener('click', () => this.logout());
        this.container.appendChild(loggedInContainer);
    }

    showLoginModal() {
        // Evita criar múltiplos modais
        if (document.querySelector('.syra-modal-overlay')) return;

        const modalOverlay = document.createElement('div');
        modalOverlay.className = 'syra-modal-overlay';
        
        modalOverlay.innerHTML = `
            <div class="syra-modal-content">
                <button class="syra-modal-close">×</button>
                <h2><span class="syra-brand-highlight">SyraID</span> Login</h2>
                <p class="syra-modal-subtitle">Use seu nome de usuário e código do app autenticador.</p>
                <form id="syraLoginForm">
                    <div class="syra-input-group">
                        <label for="syraUsername">Nome de Usuário</label>
                        <input type="text" id="syraUsername" name="username" required autocomplete="username">
                    </div>
                    <div class="syra-input-group">
                        <label for="syraTotp">Código TOTP</label>
                        <input type="text" id="syraTotp" name="totp_code" required autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}">
                    </div>
                    <p id="syra-error-message" class="syra-error-text"></p>
                    <button type="submit" class="syra-submit-btn">Entrar</button>
                </form>
            </div>
        `;

        document.body.appendChild(modalOverlay);

        const closeModal = () => document.body.removeChild(modalOverlay);

        modalOverlay.querySelector('.syra-modal-close').addEventListener('click', closeModal);
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) closeModal();
        });
        
        document.getElementById('syraLoginForm').addEventListener('submit', (e) => this.handleLoginSubmit(e));
    }

    async handleLoginSubmit(event) {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('.syra-submit-btn');
        const errorMessage = document.getElementById('syra-error-message');
        
        const username = form.elements.username.value.trim();
        const totp_code = form.elements.totp_code.value.trim();

        if (!username || !totp_code) {
            errorMessage.textContent = "Ambos os campos são obrigatórios.";
            return;
        }

        submitButton.disabled = true;
        submitButton.textContent = 'Verificando...';
        errorMessage.textContent = '';

        try {
            const response = await fetch(`${this.apiBaseUrl}/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, totp_code })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Ocorreu um erro desconhecido.');
            }

            // Sucesso!
            this.jwt = data.token;
            localStorage.setItem('syra_jwt', this.jwt);
            const payload = this.parseJwt(this.jwt);
            this.username = payload.username;
            
            // Dispara um evento customizado para a página saber do login
            this.container.dispatchEvent(new CustomEvent('syra:login', {
                detail: { token: this.jwt, payload: payload },
                bubbles: true,
                composed: true
            }));

            document.body.removeChild(document.querySelector('.syra-modal-overlay'));
            this.render();

        } catch (error) {
            errorMessage.textContent = error.message;
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Entrar';
        }
    }
    
    logout() {
        this.jwt = null;
        this.username = null;
        localStorage.removeItem('syra_jwt');
        
        // Dispara um evento customizado
        this.container.dispatchEvent(new CustomEvent('syra:logout', {
            bubbles: true,
            composed: true
        }));
        
        this.render();
    }

    injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            :root {
                --syra-dark-purple: #1F1C2C;
                --syra-lavender-gray: #928DAB;
                --syra-main-text: #EAEAEA;
                --syra-highlight: #C084FC;
                --syra-error: #FF6B6B;
            }
            .syra-login-btn {
                width: 100%; padding: 15px; border: none; border-radius: 8px;
                background: linear-gradient(to right, var(--syra-highlight), #a164df);
                color: var(--syra-dark-purple); font-size: 1.1rem; font-weight: 600; cursor: pointer;
                transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(192, 132, 252, 0.2);
                display: flex; align-items: center; justify-content: center; gap: 10px;
                font-family: 'Poppins', sans-serif;
            }
            .syra-login-btn:hover {
                transform: translateY(-3px); box-shadow: 0 6px 20px rgba(192, 132, 252, 0.4);
            }
            .syra-logged-in-container {
                display: flex; flex-direction: column; align-items: center; gap: 15px;
                padding: 15px; border-radius: 8px; background: rgba(0,0,0,0.2);
                width: 100%;
            }
            .syra-welcome-text { margin: 0; color: var(--syra-main-text); font-family: 'Poppins', sans-serif; }
            .syra-logout-btn {
                padding: 8px 20px; border: 1px solid var(--syra-lavender-gray); border-radius: 6px;
                background: transparent; color: var(--syra-lavender-gray); cursor: pointer; transition: all 0.2s;
                font-family: 'Poppins', sans-serif;
            }
            .syra-logout-btn:hover { background: var(--syra-highlight); color: var(--syra-dark-purple); border-color: var(--syra-highlight); }

            /* Estilos do Modal */
            .syra-modal-overlay {
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(5px);
                display: flex; justify-content: center; align-items: center; z-index: 1000;
            }
            .syra-modal-content {
                background: var(--syra-dark-purple); color: var(--syra-main-text);
                padding: 30px 40px; border-radius: 12px; max-width: 400px; width: 90%;
                position: relative; box-shadow: 0 8px 32px 0 rgba(0,0,0,0.37);
                border: 1px solid rgba(255, 255, 255, 0.18);
                font-family: 'Poppins', sans-serif;
            }
            .syra-modal-close {
                position: absolute; top: 10px; right: 15px; background: none; border: none;
                color: var(--syra-lavender-gray); font-size: 2rem; cursor: pointer;
            }
            .syra-modal-content h2 { font-size: 2rem; margin-bottom: 5px; text-align: center; }
            .syra-brand-highlight { background: linear-gradient(to right, var(--syra-highlight), var(--syra-main-text)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
            .syra-modal-subtitle { color: var(--syra-lavender-gray); text-align: center; margin-bottom: 25px; }
            .syra-input-group { margin-bottom: 20px; }
            .syra-input-group label { display: block; margin-bottom: 5px; color: var(--syra-lavender-gray); }
            .syra-input-group input {
                width: 100%; padding: 12px; background: rgba(255,255,255,0.1);
                border: 1px solid var(--syra-lavender-gray); border-radius: 6px;
                color: var(--syra-main-text); font-size: 1rem;
            }
            .syra-input-group input:focus { outline: none; border-color: var(--syra-highlight); }
            .syra-submit-btn {
                width: 100%; padding: 15px; border: none; border-radius: 8px;
                background: linear-gradient(to right, var(--syra-highlight), #a164df);
                color: var(--syra-dark-purple); font-size: 1.1rem; font-weight: 600;
                cursor: pointer; transition: background 0.3s;
            }
            .syra-submit-btn:disabled { background: var(--syra-lavender-gray); cursor: not-allowed; }
            .syra-error-text { color: var(--syra-error); min-height: 20px; text-align: center; margin-bottom: 10px; }
        `;
        document.head.appendChild(style);
    }
}