#include <dirent.h>
#include <iostream>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <regex.h>
#include <map>


#define FORMAT "%-20s %-10s %-20s %-10s %-10s %-10s %s %s\n"
// #define USER_LEN 20
// #define COMMAND_LEN 50
// #define PATH_LEN 100

using namespace std;

bool command_flag = false;
bool file_name_flag = false;
bool type_flag = false;
char command_arg[100];
char file_name_arg[100];
char type_arg[100];

bool is_pid(char*);
void dump_proc_info(string);
// bool is_exist(proc_info*, char*)

struct proc_info {
    string pid;
    // char user[USER_LEN];
    // char command[COMMAND_LEN];
    // char path[PATH_LEN];
    string user;
    string command;
    string path;
    vector<vector<string>> vec;  // [FD ,TYPE, NODE, NAME]
};

bool is_exist(proc_info* info, char* ino) {
    vector<vector<string>>::iterator row;
    vector<string>::iterator col;

    bool exist = false;
    for(row = info->vec.begin(); row != info->vec.end(); ++row){
        const char* node = (*row)[2].c_str();
        if(strcmp(node, ino) == 0){
            exist = true;
            break;
        }
    }

    return exist;
}

void output_header(){
    printf(FORMAT, "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME", "");
}

// check str is process id (all digit)
bool is_pid(char* str){
    for(int i = 0; i < int(strlen(str)); i++){
        if(!isdigit(str[i])) // digit -> return 1
            return false;
    }

    return true;
}

bool regex_check(const char *expression, const char *str){
    regex_t regex;
    regcomp(&regex, expression, 0);
    int retoi = regexec(&regex, str, 0, NULL, 0);

    if (retoi == 0) 
        return true;
    else
        return false;
}

void push_record(proc_info *info, const char* fd, char* type, char* node, char* name, char* err_msg){
    // cout << fd << type << node << name << err_msg << endl;

    string s_fd(fd);
    string s_type(type);
    string s_node(node);
    string s_name(name);
    string s_err_msg(err_msg);
    vector<string> record{s_fd, s_type, s_node, s_name, s_err_msg};
    info->vec.push_back(record);
}

string get_username(const char* path) {
    struct stat pid_stat;
    struct passwd *pw;

    if(!stat(path, &pid_stat)){
        pw = getpwuid(pid_stat.st_uid);
        if(pw) {
            return pw -> pw_name;
        }
    }

    return "";
}

string get_command(const char* path) {
    char comm_path[110];
    snprintf(comm_path, sizeof(comm_path), "%s%s", path, "comm");

    FILE* comm_fd;
    comm_fd = fopen(comm_path, "r");
    if(!comm_fd)
        return "";
    else{
        char command[50];
        fgets(command, sizeof(command), comm_fd);
        fclose(comm_fd);

        // remove \n
        for(int i = 0; i < int(strlen(command)); i++)
            if(command[i] == '\n')
                command[i] = '\0';
        
        // cout << command << endl;
        
        string result(command);
        return result;
    } 
}

void read_path_type(char* path, char* type) {
    struct stat s;
    if(stat(path, &s) != 0)
        return;
    
    if(S_ISDIR(s.st_mode))
        strcpy(type, "DIR");
    else if(S_ISCHR(s.st_mode))
        strcpy(type, "CHR");
    else if(S_ISFIFO(s.st_mode))
        strcpy(type, "FIFO");
    else if(S_ISSOCK(s.st_mode))
        strcpy(type, "SOCK");
    else if(S_ISREG(s.st_mode))
        strcpy(type, "REG");
    else
        strcpy(type, "unknown");
}

// void read_inode(char* path, char* node){
//     struct stat s;
//     if(stat(path, &s) != 0)
//         return;
//     snprintf(node, sizeof(node), "%lu", s.st_ino);
// }

ino_t get_ino(const char* path){
    struct stat s;
    if(stat(path, &s) != 0)
        return 0;
    return s.st_ino;
}

void read_type(const char* fd, proc_info *info) {
    char fd_path[200] = "", fd_tmp[10] = "", type[10] = "", node[20] = "", name[200] = "", err_msg[50] = "";
    char link_dest[PATH_MAX];
    ssize_t link_dest_size;

    snprintf(fd_path, sizeof(fd_path), "%s%s", (info -> path).c_str(), fd);
    
    if((link_dest_size = readlink(fd_path, link_dest, sizeof(link_dest)-1)) < 0){
        snprintf(name, sizeof(name), "%s", fd_path);
        snprintf(type, sizeof(type), "%s", "unknown");
        snprintf(err_msg, sizeof(err_msg), "(%s)", "Permission denied");
        node[0] = '\0';
    }
    else{
        link_dest[link_dest_size] = '\0';
        read_path_type(fd_path, type);
        snprintf(node, sizeof(node), "%lu", get_ino(fd_path));
        strcpy(name, link_dest);
    }

    if(strcmp(fd, "root") == 0)
        strcpy(fd_tmp, "rtd");
    else if(strcmp(fd, "exe") == 0)
        strcpy(fd_tmp, "txt");
    else
        strcpy(fd_tmp, fd);

    if(type_flag && !regex_check(type_arg, type))
        return;
    
    if(file_name_flag && !regex_check(file_name_arg, name))
        return;

    push_record(info, fd_tmp, type, node, name, err_msg);
    
}

void parse_map(char* line, char *node, char* name) {
    int space_count = 0;
    int ino_idx = 0, name_idx = 0;
    for(int i = 0; i < int(strlen(line)); i++){
        if(line[i] == ' '){
            space_count++;
            continue;
        }

        if(space_count == 4){
            node[ino_idx] = line[i];
            ino_idx++;
        }

        if(space_count > 4 && line[i] != '\n'){
            name[name_idx] = line[i];
            name_idx++;
        }
    }

    if(node[ino_idx] != '\0')
        node[ino_idx] = '\0';
    if(name[name_idx] != '\0')
        name[name_idx] = '\0';
}

bool is_deleted(char* name) {
    if(regex_check("deleted", name)){
        name[strlen(name)-9] = '\0';
        return true;
    }
    return false;
}

void read_maps(proc_info *info) {
    char maps_path[100] = "", fd[10] = "", type[10] = "", node[20] = "", name[200] = "", err_msg[50] = "";
    map<int, int> inode;
    FILE* maps_fd;

    snprintf(maps_path, sizeof(maps_path), "%s%s", (info->path).c_str(), "maps");

    maps_fd = fopen(maps_path, "r");
    if (!maps_fd){
        return;
    }
    else{
        char line[200];
        while(fgets(line, sizeof(line), maps_fd)) {
            err_msg[0] = '\0';
            parse_map(line, node, name);

            if(inode.find(atoi(node)) != inode.end() || atoi(node) == 0)
                continue;
            inode[atoi(node)] = 1;

            if(is_deleted(name)){
                strcpy(fd, "DEL");
                strcpy(type, "unknown");
            }
            else{
                strcpy(fd, "mem");
                read_path_type(name, type);
            }

            if(type_flag && !regex_check(type_arg, type))
                continue;
    
            if(file_name_flag && !regex_check(file_name_arg, name))
                continue;

            if(!is_exist(info, node)) 
                push_record(info, fd, type, node, name, err_msg);
        }
    }
    fclose(maps_fd);
}

void read_fd_mode(char* path, char* file_name, char* fd){
    struct stat s;
    if(lstat(path, &s) == -1)
        return;
    
    if((s.st_mode & S_IREAD) && (s.st_mode & S_IWRITE))
        snprintf(fd, sizeof(fd)-1, "%s%s", file_name, "u");
    else if(s.st_mode & S_IRUSR)
        snprintf(fd, sizeof(fd)-1, "%s%s", file_name, "r");
    else if(s.st_mode & S_IWUSR)
        snprintf(fd, sizeof(fd)-1, "%s%s", file_name, "w");
}

// void is_pipe_or_fifo_type(char* name, char* type, char* node){
//     if(regex_check("pipi"))
// }

void read_fd(proc_info* info) {
    char fd_dir_path[100] = "", fd[10] = "", type[10] = "", node[30] = "", name[200] = "", err_msg[50] = "";
    
    snprintf(fd_dir_path, sizeof(fd_dir_path), "%s%s", (info->path).c_str(), "fd");
    DIR* dir = opendir(fd_dir_path);
    if(!dir) {
        snprintf(name, sizeof(name), "%s", fd_dir_path);
        snprintf(err_msg, sizeof(err_msg), "(%s)", "Permission denied");
        strcpy(fd, "NOFD");
        // node[0] = '\0';
    }
    else{
        struct dirent* direntp;
        while((direntp = readdir(dir))) {
            if(strcmp(direntp->d_name, ".") == 0 || strcmp(direntp->d_name, "..") == 0)
                continue;

            char fd_path[500] = "", link_dest[100] = "";
            int link_dest_size;

            snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir_path, direntp->d_name);
            if((link_dest_size = readlink(fd_path, link_dest, sizeof(link_dest)-1)) < 0) 
                continue;
            else{
                link_dest[link_dest_size] = '\0';
                read_fd_mode(fd_path, direntp->d_name, fd);
                read_path_type(fd_path, type);
                snprintf(node, sizeof(node), "%lu", get_ino(fd_path));
                strcpy(name, link_dest);

                is_deleted(name);
                // if(is_deleted(name))
                //     strcpy(type, "unknown");
            }

            if(type_flag && !regex_check(type_arg, type))
                continue;
    
            if(file_name_flag && !regex_check(file_name_arg, name))
                continue;

            push_record(info, fd, type, node, name, err_msg);
        }

        closedir(dir);
    }
}

void output_record(proc_info* info){
    vector<vector<string>>::iterator row;
    vector<string>::iterator col;

    for(row = info->vec.begin(); row != info->vec.end(); ++row){
        const char* command = (info->command).c_str();
        const char* user = (info->user).c_str();
        const char* pid = (info->pid).c_str();
        const char* fd = (*row)[0].c_str();
        const char* type = (*row)[1].c_str();
        const char* node = (*row)[2].c_str();
        const char* name = (*row)[3].c_str();
        const char* err_msg = (*row)[4].c_str();

        printf(FORMAT, command, pid, user, fd, type, node, name, err_msg);
        // char 
        // for(col = row->begin(); col != row->end(); ++col){
            
        // }
    }
}

void dump_proc_info(string pid){
    struct proc_info info;

    // info.pid = stoi(pid);
    info.pid = pid;
    info.path = "/proc/" + pid + "/";
    info.user = get_username(info.path.c_str());
    info.command = get_command(info.path.c_str());

    if(command_flag && !regex_check(command_arg, info.command.c_str()))
        return;

    read_type("cwd", &info);
    read_type("root", &info);
    read_type("exe", &info);
    read_maps(&info);
    read_fd(&info);

    output_record(&info);
}

int main(int argc, char** argv){

    if (argc > 1) {
        int cmd_opt;
        while((cmd_opt = getopt(argc, argv, "c:t:f:")) != -1){
            switch (cmd_opt){
                case 'c':
                    command_flag = true;
                    strcpy(command_arg, optarg);
                    break;

                case 't':
                    if(strcmp("REG", optarg) == 0 || strcmp("CHR", optarg) == 0 ||
                       strcmp("DIR", optarg) == 0 || strcmp("FIFO", optarg) == 0 ||
                       strcmp("SOCK", optarg) == 0 || strcmp("unknown", optarg) == 0)
                    {      
                        type_flag = true;
                        strcpy(type_arg, optarg);
                    }
                    else {
                        printf("Invalid TYPE option.\n");
                        return 0;
                    }
                    break;
                    
                case 'f':
                    file_name_flag = true;
                    strcpy(file_name_arg, optarg);
                    break;

            }
        }
    }

    output_header();
    DIR* dir = opendir("/proc");
    struct dirent* direntp;

    while((direntp = readdir(dir)) != NULL) {
        if (is_pid(direntp -> d_name))
            dump_proc_info(direntp -> d_name);
    }

    closedir(dir);
}