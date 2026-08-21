FROM mcr.microsoft.com/devcontainers/base:trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        adb \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME=vscode

RUN python3 -m venv /opt/venv \
    && chown -R $USERNAME:$USERNAME /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

RUN mkdir -p /commandhistory \
    && touch /commandhistory/.bash_history /commandhistory/.zsh_history \
    && chown -R $USERNAME /commandhistory \
    && echo "export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" >> "/home/$USERNAME/.bashrc" \
    && echo "export HISTFILE=/commandhistory/.zsh_history\nsetopt INC_APPEND_HISTORY" >> "/home/$USERNAME/.zshrc"
