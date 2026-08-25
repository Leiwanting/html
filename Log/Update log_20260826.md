# Update Log 2026-08-26
> ~~***嗯对 今天没更新***~~

## 你知道吗今天我在水日志
LaTeX公式我随便写几个吧XD:

$$
\begin{aligned}
\mathcal{L}_{\text{VAE}}(\theta, \phi) &= \mathbb{E}_{q_\phi(\mathbf{z} \mid \mathbf{x})}\left[\log p_\theta(\mathbf{x} \mid \mathbf{z})\right] - D_{\text{KL}}\left(q_\phi(\mathbf{z} \mid \mathbf{x}) \,\|\, p_\theta(\mathbf{z})\right) \\
&= \underbrace{\frac{1}{N}\sum_{i=1}^{N}\left[\log p_\theta(\mathbf{x}^{(i)} \mid \mathbf{z}^{(i)})\right]}_{\text{Reconstruction Loss}} - \underbrace{\frac{1}{2}\sum_{j=1}^{J}\left(1 + \log\left(\sigma_j^2\right) - \mu_j^2 - \sigma_j^2\right)}_{\text{KL Divergence}} \\
&= \int_{\mathcal{Z}} q_\phi(\mathbf{z} \mid \mathbf{x}) \log \frac{p_\theta(\mathbf{x}, \mathbf{z})}{q_\phi(\mathbf{z} \mid \mathbf{x})} \, d\mathbf{z} \\
&= \mathbb{E}_{\mathbf{z} \sim \mathcal{N}(\boldsymbol{\mu}, \text{diag}(\boldsymbol{\sigma}^2))}\left[-\frac{1}{2}\left\|\mathbf{x} - \boldsymbol{\mu}_\theta(\mathbf{z})\right\|_2^2\right] - \frac{1}{2}\sum_{j=1}^{J}\left(1 + \log \sigma_j^2 - \mu_j^2 - \sigma_j^2\right) \\
&= -\frac{1}{2}\sum_{i=1}^{N}\left[\frac{\left\|\mathbf{x}^{(i)} - \mathbf{f}_\theta(\mathbf{z}^{(i)})\right\|^2}{\beta} + \sum_{j=1}^{J}\left(1 + \log\left(\left(\sigma_j^{(i)}\right)^2\right) - \left(\mu_j^{(i)}\right)^2 - \left(\sigma_j^{(i)}\right)^2\right)\right] + \mathcal{O}\left(\frac{1}{\sqrt{N}}\right)
\end{aligned}
$$

$$
\begin{aligned}
Z(\beta, V, N) &= \frac{1}{N! h^{3N}} \int_{\mathbb{R}^{6N}} \exp\left(-\beta \mathcal{H}(\mathbf{q}, \mathbf{p})\right) \, d^{3N}q \, d^{3N}p \\
&= \frac{1}{N! h^{3N}} \int_{\mathbb{R}^{3N}} \exp\left(-\beta \sum_{i=1}^{N} \frac{\mathbf{p}_i^2}{2m_i}\right) d^{3N}p \int_{\mathbb{R}^{3N}} \exp\left(-\beta \sum_{i<j} V(|\mathbf{q}_i - \mathbf{q}_j|)\right) d^{3N}q \\
&= \frac{1}{N!} \left(\frac{2\pi m}{\beta h^2}\right)^{\frac{3N}{2}} \int_{V^N} \exp\left(-\beta \sum_{i<j} \phi(r_{ij})\right) d^{3N}r \\
&= \frac{1}{N!} \left(\frac{V}{\lambda_T^3}\right)^N \left[1 + \frac{N(N-1)}{2V} \int_0^\infty \left(e^{-\beta \phi(r)} - 1\right) 4\pi r^2 \, dr + \mathcal{O}\left(\frac{N^3}{V^2}\right)\right] \\
&= \frac{1}{N!} \left(\frac{V}{\lambda_T^3}\right)^N \exp\left(\frac{N^2}{2V} \int_0^\infty f(r) 4\pi r^2 \, dr\right) \cdot \left[1 + \mathcal{O}\left(\frac{N}{V}\right)\right] \\
&\approx \frac{1}{N!} \left(\frac{V}{\lambda_T^3}\right)^N \exp\left(\frac{N^2 B_2(T)}{V}\right) \quad \text{其中} \quad B_2(T) = -2\pi \int_0^\infty r^2 \left(e^{-\beta \phi(r)} - 1\right) dr
\end{aligned}
$$

$$
\begin{aligned}
\min_{\mathbf{W}^{(1)}, \dots, \mathbf{W}^{(L)}, \mathbf{b}^{(1)}, \dots, \mathbf{b}^{(L)}} \mathcal{L}_{\text{total}} &= \underbrace{\frac{1}{N}\sum_{n=1}^{N} \mathcal{L}_{\text{CE}}\left(\mathbf{y}^{(n)}, \hat{\mathbf{y}}^{(n)}\right)}_{\text{Data Loss}} + \underbrace{\lambda \sum_{\ell=1}^{L} \left(\left\|\mathbf{W}^{(\ell)}\right\|_F^2 + \left\|\mathbf{b}^{(\ell)}\right\|_2^2\right)}_{\text{L2 Regularization}} \\
\text{s.t.} \quad \mathbf{a}^{(0)} &= \mathbf{x} \\
\mathbf{z}^{(\ell)} &= \mathbf{W}^{(\ell)} \mathbf{a}^{(\ell-1)} + \mathbf{b}^{(\ell)}, \quad \ell = 1, \dots, L \\
\mathbf{a}^{(\ell)} &= \sigma\left(\mathbf{z}^{(\ell)}\right) = \frac{1}{1 + \exp\left(-\mathbf{z}^{(\ell)}\right)}, \quad \ell = 1, \dots, L-1 \\
\hat{\mathbf{y}} &= \text{softmax}\left(\mathbf{z}^{(L)}\right)_i = \frac{\exp\left(z_i^{(L)}\right)}{\sum_{j=1}^{K} \exp\left(z_j^{(L)}\right)} \\
\frac{\partial \mathcal{L}}{\partial \mathbf{W}^{(\ell)}} &= \frac{\partial \mathcal{L}}{\partial \mathbf{z}^{(\ell)}} \cdot \frac{\partial \mathbf{z}^{(\ell)}}{\partial \mathbf{W}^{(\ell)}} = \boldsymbol{\delta}^{(\ell)} \left(\mathbf{a}^{(\ell-1)}\right)^\top \\
\boldsymbol{\delta}^{(\ell)} &= \begin{cases}
\left(\hat{\mathbf{y}} - \mathbf{y}\right) \odot \sigma'\left(\mathbf{z}^{(L)}\right), & \ell = L \\
\left(\left(\mathbf{W}^{(\ell+1)}\right)^\top \boldsymbol{\delta}^{(\ell+1)}\right) \odot \sigma'\left(\mathbf{z}^{(\ell)}\right), & \ell = L-1, \dots, 1
\end{cases} \\
\mathbf{W}^{(\ell)}_{t+1} &= \mathbf{W}^{(\ell)}_t - \eta_t \left(\frac{\partial \mathcal{L}}{\partial \mathbf{W}^{(\ell)}_t} + 2\lambda \mathbf{W}^{(\ell)}_t\right) + \beta \left(\mathbf{W}^{(\ell)}_t - \mathbf{W}^{(\ell)}_{t-1}\right) + \mathcal{N}\left(0, \frac{\eta_t \tau}{N}\mathbf{I}\right)
\end{aligned}
$$

$$
\begin{aligned}
R_{\mu\nu} - \frac{1}{2}g_{\mu\nu}R + \Lambda g_{\mu\nu} &= \frac{8\pi G}{c^4}T_{\mu\nu} \\
T_{\mu\nu} &= \left(\rho + \frac{p}{c^2}\right)u_\mu u_\nu + p g_{\mu\nu} + \Pi_{\mu\nu} + q_\mu u_\nu + q_\nu u_\mu \\
\Gamma^\lambda_{\mu\nu} &= \frac{1}{2}g^{\lambda\sigma}\left(\partial_\mu g_{\nu\sigma} + \partial_\nu g_{\mu\sigma} - \partial_\sigma g_{\mu\nu}\right) \\
R^\rho_{\sigma\mu\nu} &= \partial_\mu \Gamma^\rho_{\nu\sigma} - \partial_\nu \Gamma^\rho_{\mu\sigma} + \Gamma^\rho_{\mu\lambda}\Gamma^\lambda_{\nu\sigma} - \Gamma^\rho_{\nu\lambda}\Gamma^\lambda_{\mu\sigma} \\
R_{\mu\nu} &= R^\lambda_{\mu\lambda\nu} = \partial_\lambda \Gamma^\lambda_{\mu\nu} - \partial_\nu \Gamma^\lambda_{\mu\lambda} + \Gamma^\lambda_{\lambda\rho}\Gamma^\rho_{\mu\nu} - \Gamma^\lambda_{\nu\rho}\Gamma^\rho_{\mu\lambda} \\
G_{\mu\nu} &= R_{\mu\nu} - \frac{1}{2}g_{\mu\nu}R = \frac{8\pi G}{c^4}\left[\left(\rho + \frac{p}{c^2}\right)u_\mu u_\nu + p g_{\mu\nu}\right] - \Lambda g_{\mu\nu} \\
\nabla_\mu T^{\mu\nu} &= \partial_\mu T^{\mu\nu} + \Gamma^\mu_{\mu\lambda}T^{\lambda\nu} + \Gamma^\nu_{\mu\lambda}T^{\mu\lambda} = 0 \\
ds^2 &= g_{\mu\nu}dx^\mu dx^\nu = -\left(1 - \frac{2GM}{rc^2}\right)c^2dt^2 + \left(1 - \frac{2GM}{rc^2}\right)^{-1}dr^2 + r^2\left(d\theta^2 + \sin^2\theta \, d\phi^2\right)
\end{aligned}
$$

$$
\begin{aligned}
Z[J] &= \int \mathcal{D}\phi \, \exp\left(\frac{i}{\hbar}\int d^4x \left[\mathcal{L}(\phi, \partial_\mu\phi) + J(x)\phi(x)\right]\right) \\
&= \int \mathcal{D}\phi \, \exp\left(\frac{i}{\hbar}\int d^4x \left[\frac{1}{2}\partial_\mu\phi\partial^\mu\phi - \frac{1}{2}m^2\phi^2 - \frac{\lambda}{4!}\phi^4 + J\phi\right]\right) \\
&= \exp\left(-\frac{i\lambda}{4!\hbar}\int d^4x \left(\frac{\hbar}{i}\frac{\delta}{\delta J(x)}\right)^4\right) \cdot Z_0[J] \\
Z_0[J] &= \exp\left(-\frac{i}{2\hbar}\int d^4x \, d^4y \, J(x)\Delta_F(x-y)J(y)\right) \\
\Delta_F(x-y) &= \int \frac{d^4k}{(2\pi)^4} \frac{i e^{-ik(x-y)}}{k^2 - m^2 + i\epsilon} \\
\langle \Omega | T\{\phi(x_1)\phi(x_2)\} | \Omega \rangle &= \frac{1}{Z[0]}\left.\frac{\hbar}{i}\frac{\delta}{\delta J(x_1)}\frac{\hbar}{i}\frac{\delta}{\delta J(x_2)} Z[J]\right|_{J=0} \\
&= \Delta_F(x_1-x_2) - \frac{i\lambda}{2\hbar}\int d^4z \, \Delta_F(x_1-z)\Delta_F(0)\Delta_F(z-x_2) + \mathcal{O}(\lambda^2) \\
\mathcal{M}(p_1,p_2 \to p_3,p_4) &= (-i\lambda) + (-i\lambda)^2 \left[iV(s) + iV(t) + iV(u)\right] + \mathcal{O}(\lambda^3) \\
V(s) &= \frac{1}{2}\int \frac{d^4k}{(2\pi)^4} \frac{i}{(k^2-m^2+i\epsilon)((p_1+p_2-k)^2-m^2+i\epsilon)} \\
&= \frac{i}{32\pi^2}\int_0^1 dx \, \log\left(\frac{m^2 - x(1-x)s - i\epsilon}{\mu^2}\right) + \text{const}
\end{aligned}
$$
