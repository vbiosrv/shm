package Core::VKHunter;

use v5.14;
use parent 'Core::Base';
use Core::Utils qw(now);
use Core::System::ServiceManager qw(get_service);
use IPC::System::Simple qw(capture system);
use File::Temp qw(tempfile);
use JSON::PP;

sub table { return 'vk_hunter' };

sub structure {
    return {
        id => {
            type => 'number',
            key => 1,
            auto_increment => 1,
        },
        user_id => {
            type => 'number',
            required => 1,
            title => 'ID пользователя',
        },
        target_ip => {
            type => 'text',
            title => 'Найденный IP',
        },
        subnet_name => {
            type => 'text',
            title => 'Имя подсети',
        },
        subnet_id => {
            type => 'text',
            title => 'ID подсети',
        },
        floating_id => {
            type => 'text',
            title => 'ID Floating IP',
        },
        attempts => {
            type => 'number',
            default => 0,
            title => 'Количество попыток',
        },
        status => {
            type => 'text',
            default => 'running',
            enum => ['running', 'completed', 'failed', 'stopped'],
            title => 'Статус охоты',
        },
        saved_ip => {
            type => 'text',
            title => 'Сохраненный IP (защита от удаления)',
        },
        log_file => {
            type => 'text',
            title => 'Путь к лог-файлу',
        },
        created => {
            type => 'now',
            title => 'Дата создания',
        },
        updated => {
            type => 'date',
            title => 'Дата обновления',
        },
        settings => {
            type => 'json',
            value => {},
            title => 'Настройки охоты',
        },
    };
}

sub init {
    my $self = shift;
    
    unless ( $self->{id} ) {
        $self->{id} = $self->user_id;
    }
    
    return $self;
}

# Запуск новой охоты
sub start_hunt {
    my $self = shift;
    my %args = (
        target_subnets => ['ext-sub39', 'ext-sub40', 'ext-sub33', 'ext-sub35'],
        prefixes => ['95.', '90.', '5.'],
        saved_ip => undef,
        max_attempts => 0, # 0 = бесконечно
        notify_callback => '/vk_hunter_result',
        @_,
    );
    
    my $user_id = $self->user_id;
    my $report = get_service('report');
    
    # Проверяем, нет ли уже активной охоты
    my ($active) = $self->_list(
        where => {
            user_id => $user_id,
            status => 'running',
        }
    );
    
    if ($active) {
        $report->add_error('У вас уже есть активная охота');
        return undef;
    }
    
    # Создаем временный файл для лога
    my ($fh, $log_file) = tempfile(
        "vk_hunter_XXXXXX",
        DIR => '/tmp',
        SUFFIX => '.log',
        UNLINK => 0,
    );
    close $fh;
    
    # Создаем запись в БД
    my $hunt_id = $self->add(
        user_id => $user_id,
        attempts => 0,
        status => 'running',
        saved_ip => $args{saved_ip},
        log_file => $log_file,
        settings => {
            target_subnets => $args{target_subnets},
            prefixes => $args{prefixes},
            max_attempts => $args{max_attempts},
            notify_callback => $args{notify_callback},
        },
    );
    
    # Запускаем охоту в фоне
    my $pid = fork();
    if ($pid == 0) {
        # Дочерний процесс
        $self->_run_hunter($hunt_id, \%args);
        exit(0);
    } elsif ($pid > 0) {
        # Родительский процесс
        $self->id($hunt_id)->set(pid => $pid);
        return $hunt_id;
    } else {
        $report->add_error('Не удалось запустить процесс');
        return undef;
    }
}

# Остановка охоты
sub stop_hunt {
    my $self = shift;
    my $hunt_id = shift || $self->id;
    
    my $hunt = $self->id($hunt_id);
    return undef unless $hunt;
    
    if ($hunt->get_pid) {
        kill('TERM', $hunt->get_pid);
        sleep(1);
        kill('KILL', $hunt->get_pid) if kill(0, $hunt->get_pid);
    }
    
    $hunt->set(
        status => 'stopped',
        updated => now(),
    );
    
    return 1;
}

# Получить статус охоты
sub get_status {
    my $self = shift;
    my $hunt_id = shift || $self->id;
    
    my $hunt = $self->id($hunt_id);
    return undef unless $hunt;
    
    my $log_content = '';
    if (-f $hunt->get_log_file) {
        open(my $fh, '<', $hunt->get_log_file);
        local $/;
        $log_content = <$fh> // '';
        close $fh;
    }
    
    return {
        id => $hunt->id,
        status => $hunt->get_status,
        attempts => $hunt->get_attempts,
        target_ip => $hunt->get_target_ip,
        log => $log_content,
        created => $hunt->get_created,
    };
}

# Внутренний метод - запуск hunter скрипта
sub _run_hunter {
    my ($self, $hunt_id, $args) = @_;
    
    # Формируем команду с параметрами
    my $subnets_str = join(' ', @{$args->{target_subnets}});
    my $prefixes_str = join(' ', @{$args->{prefixes}});
    
    # Создаем временный OpenRC файл
    my $config = get_service('config');
    my $openrc_content = $self->_generate_openrc($config);
    
    my ($rc_fh, $rc_file) = tempfile(
        "openrc_XXXXXX",
        DIR => '/tmp',
        SUFFIX => '.sh',
        UNLINK => 0,
    );
    print $rc_fh $openrc_content;
    close $rc_fh;
    chmod 0600, $rc_file;
    
    # Создаем hunter скрипт
    my $hunter_script = $self->_generate_hunter_script(
        hunt_id => $hunt_id,
        target_subnets => $args->{target_subnets},
        prefixes => $args->{prefixes},
        saved_ip => $args->{saved_ip},
        openrc_file => $rc_file,
    );
    
    my ($script_fh, $script_file) = tempfile(
        "hunter_XXXXXX",
        DIR => '/tmp',
        SUFFIX => '.sh',
        UNLINK => 0,
    );
    print $script_fh $hunter_script;
    close $script_fh;
    chmod 0700, $script_file;
    
    # Запускаем скрипт
    my $log_file = $self->id($hunt_id)->get_log_file;
    
    # Перенаправляем вывод в лог
    open(my $log_fh, '>>', $log_file);
    open(STDOUT, '>&', $log_fh);
    open(STDERR, '>&', $log_fh);
    
    # Запускаем hunter
    system($script_file);
    
    # Очистка
    close $log_fh;
    unlink $rc_file if -f $rc_file;
    unlink $script_file if -f $script_file;
}

# Генерация OpenRC файла из конфига
sub _generate_openrc {
    my ($self, $config) = @_;
    
    my $os_config = $config->data_by_name('openstack') // {};
    
    return <<"OPENRC";
export OS_AUTH_URL=${os_config->{auth_url} || 'https://api.selvpc.ru/identity/v3'}
export OS_USERNAME=${os_config->{username} || die("OS_USERNAME not set")}
export OS_PASSWORD=${os_config->{password} || die("OS_PASSWORD not set")}
export OS_USER_DOMAIN_NAME=${os_config->{user_domain_name} || 'users'}
export OS_PROJECT_NAME=${os_config->{project_name} || die("OS_PROJECT_NAME not set")}
export OS_PROJECT_DOMAIN_NAME=${os_config->{project_domain_name} || 'Default'}
export OS_IDENTITY_API_VERSION=3
export OS_INTERFACE=public
OPENRC
}

# Генерация hunter скрипта
sub _generate_hunter_script {
    my ($self, %params) = @_;
    
    my $subnets_str = join(' ', @{$params{target_subnets}});
    my $prefixes_str = join(' ', @{$params{prefixes}});
    my $saved_ip = $params{saved_ip} // '';
    my $hunt_id = $params{hunt_id};
    my $openrc_file = $params{openrc_file};
    
    return <<"HUNTER";
#!/bin/bash

# --- НАСТРОЙКИ ДЛЯ ЭТОЙ ОХОТЫ ---
HUNT_ID="$hunt_id"
TARGET_SUBNETS=($subnets_str)
PREFIXES=($prefixes_str)
SAVED_IP="$saved_ip"
OPENRC_FILE="$openrc_file"

# Задержки
MIN_DELAY=3
MAX_DELAY=7

# Цвета
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
CYAN='\\033[0;36m'
RED='\\033[0;31m'
NC='\\033[0m'

echo "--- VK Cloud Subnet Hunter (Managed by SHM) ---"
echo "Hunt ID: \$HUNT_ID"
echo ""

# Загружаем OpenRC
echo "🔍 Загрузка OpenRC файла..."
source "\$OPENRC_FILE"
if [ \$? -ne 0 ]; then
    echo -e "\${RED}⛔️ ОШИБКА: Не удалось загрузить OpenRC\${NC}"
    exit 1
fi
echo -e "\${GREEN}✅ OpenRC загружен\${NC}"

# Функция обновления статуса в БД через API SHM
update_status() {
    local status=\$1
    local attempts=\$2
    local ip=\$3
    
    # Здесь можно вызвать внутренний API SHM для обновления статуса
    # Например, через HTTP запрос к localhost
    curl -s -X POST "http://localhost:8080/api/internal/vk_hunter/update" \\
        -H "Content-Type: application/json" \\
        -d "{\\"hunt_id\\":\\"\$HUNT_ID\\",\\"status\\":\\"\$status\\",\\"attempts\\":\$attempts,\\"ip\\":\\"\$ip\\"}" > /dev/null
}

# 1. Находим ID внешней сети
echo "🔍 Поиск внешней сети..."
NET_ID=\$(openstack network list --external -f value -c ID | head -n 1)
if [ -z "\$NET_ID" ]; then
    echo -e "\${RED}⛔️ ОШИБКА: Не найдена внешняя сеть.\${NC}"
    update_status "failed" 0 ""
    exit 1
fi
NET_NAME=\$(openstack network show "\$NET_ID" -f value -c name 2>/dev/null)
echo -e "\${GREEN}✅ Внешняя сеть: \$NET_NAME (\$NET_ID)\${NC}"
echo ""

# 2. Собираем ID подсетей по именам
echo "🔍 Ищем ID для указанных подсетей..."
declare -A SUBNET_MAP
VALID_SUBNETS=()
SUBNET_NAMES=()

ALL_SUBNETS=\$(openstack subnet list -f value -c ID -c Name 2>/dev/null)

for SUBNET_NAME in "\${TARGET_SUBNETS[@]}"; do
    echo -n "   • \$SUBNET_NAME... "
    
    S_ID=\$(echo "\$ALL_SUBNETS" | awk -v name="\$SUBNET_NAME" '\$2 == name {print \$1}')
    
    if [ ! -z "\$S_ID" ]; then
        echo -e "\${GREEN}✅ НАЙДЕНА\${NC}"
        SUBNET_MAP[\$SUBNET_NAME]=\$S_ID
        VALID_SUBNETS+=("\$S_ID")
        SUBNET_NAMES+=("\$SUBNET_NAME")
    else
        echo -e "\${RED}❌ НЕ НАЙДЕНА\${NC}"
    fi
done

if [ \${#VALID_SUBNETS[@]} -eq 0 ]; then
    echo -e "\${RED}⛔️ ОШИБКА: Ни одна из указанных подсетей не найдена.\${NC}"
    update_status "failed" 0 ""
    exit 1
fi

echo ""
echo -e "\${GREEN}✅ Найдено подсетей: \${#VALID_SUBNETS[@]}\${NC}"
echo ""

printf "\n\${CYAN}%-4s | %-16s | %-36s | %-20s\${NC}\\n" "№" "IP Адрес" "Подсеть" "Статус"
echo "--------------------------------------------------------------------------------------------------------"

COUNT=0

while true; do
    for i in "\${!VALID_SUBNETS[@]}"; do
        CURRENT_SUB_ID="\${VALID_SUBNETS[\$i]}"
        CURRENT_SUB_NAME="\${SUBNET_NAMES[\$i]}"
        ((COUNT++))
        
        CURRENT_DELAY=\$(( ( RANDOM % (MAX_DELAY - MIN_DELAY + 1) ) + MIN_DELAY ))
        
        # ОЧИСТКА (кроме SAVED_IP)
        FLOATING_IPS=\$(openstack floating ip list -f value -c ID -c "Floating IP Address" 2>/dev/null)
        
        while read -r id ip; do
            if [ ! -z "\$id" ] && [ "\$id" != "ID" ] && [ "\$ip" != "\$SAVED_IP" ]; then
                openstack floating ip delete "\$id" > /dev/null 2>&1
            fi
        done <<< "\$FLOATING_IPS"
        
        sleep 1
        
        # СОЗДАНИЕ В КОНКРЕТНОЙ ПОДСЕТИ
        OUTPUT=\$(openstack floating ip create "\$NET_ID" --subnet "\$CURRENT_SUB_ID" -f value -c floating_ip_address -c id 2>&1)
        EXIT_CODE=\$?
        
        if [ \$EXIT_CODE -ne 0 ]; then
            if [[ "\$OUTPUT" == *"Quota exceeded"* ]]; then
                printf "%-4s | %-16s | %-36s | %b\\n" "\$COUNT" "---" "\${CURRENT_SUB_NAME}" "\${YELLOW}❌ Квота исчерпана\${NC}"
            else
                printf "%-4s | %-16s | %-36s | %b\\n" "\$COUNT" "ОШИБКА" "\${CURRENT_SUB_NAME}" "\${RED}❌ Ошибка создания\${NC}"
            fi
            sleep 2
            continue
        fi
        
        NEW_IP=\$(echo "\$OUTPUT" | awk '{print \$1}')
        NEW_ID=\$(echo "\$OUTPUT" | awk '{print \$2}')
        
        # ПРОВЕРКА
        MATCH=0
        for PRE in "\${PREFIXES[@]}"; do
            if [[ "\$NEW_IP" == "\$PRE"* ]]; then
                MATCH=1
                break
            fi
        done
        
        if [ \$MATCH -eq 1 ]; then
            printf "%-4s | %-16s | %-36s | %b\\n" "\$COUNT" "\$NEW_IP" "\${CURRENT_SUB_NAME}" "\${GREEN}✅✅✅ БИНГО! НАЙДЕН! ✅✅✅\${NC}"
            echo ""
            echo "══════════════════════════════════════════════════════════════════════════════════════════════════"
            echo -e "\${GREEN}🎯 Пойман целевой IP!\${NC}"
            echo "══════════════════════════════════════════════════════════════════════════════════════════════════"
            echo "   IP адрес:     \$NEW_IP"
            echo "   ID floating:  \$NEW_ID"
            echo "   Подсеть:      \$CURRENT_SUB_NAME"
            echo "   ID подсети:   \$CURRENT_SUB_ID"
            echo "   Попытка #\$COUNT"
            echo "   Время:        \$(date '+%Y-%m-%d %H:%M:%S')"
            echo "══════════════════════════════════════════════════════════════════════════════════════════════════"
            
            # Сохраняем результат
            update_status "completed" \$COUNT "\$NEW_IP"
            
            # Сохраняем в лог проекта
            echo "\$(date '+%Y-%m-%d %H:%M:%S') | \$NEW_IP | \$CURRENT_SUB_NAME | \$CURRENT_SUB_ID" >> /tmp/vk_hunter_success.log
            
            exit 0
        else
            printf "%-4s | %-16s | %-36s | %b\\n" "\$COUNT" "\$NEW_IP" "\${CURRENT_SUB_NAME}" "\${RED}❌ Не подходит\${NC}"
        fi
        
        update_status "running" \$COUNT ""
        
        sleep \$CURRENT_DELAY
    done
    
    if [ \$((COUNT % 20)) -eq 0 ]; then
        echo "--------------------------------------------------------------------------------------------------------"
        echo -e "\${CYAN}📊 Статистика: Попыток: \$COUNT | Активных подсетей: \${#VALID_SUBNETS[@]}\${NC}"
        echo "--------------------------------------------------------------------------------------------------------"
    fi
done
HUNTER
}

1;
