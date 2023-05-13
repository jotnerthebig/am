#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define PASSWD_FILE "/etc/passwd"
#define GROUP_FILE "/etc/group"

typedef struct
{
	char *username;
	char *password;
	int uid;
	int gid;
	char *personal_data;
	char *homedir;
	char *shell;

} passwd_t;

passwd_t *passwd_d = NULL;
int passwd_c = 0;

typedef struct
{
	char *name;
	char *password;
	int gid;
	char *members;
} group_t;

group_t *group_d = NULL;
int group_c = 0;

char *_strstr(char *instr, char **substr, char splitter);
char* _fread(char *fn);
int _fparse(char *buf, char splitter, _Bool (*handler)(char*));
_Bool _fclose(FILE *fd);
_Bool add_passwd_d(char *buffer);
void free_passwd_d();
_Bool add_groups_d(char *buffer);
void free_groups_d();
void display_matrix_d();
char is_in_group(int user, int group);

int main(void)
{
	char *fbuf = NULL;
	if((fbuf = _fread(PASSWD_FILE)) != NULL)
	{
		_fparse(fbuf, 0, add_passwd_d);
	}
	else
	{
		printf("error reading '" PASSWD_FILE "' file\n");
		exit(1);
	}
	free(fbuf);

	if((fbuf = _fread(GROUP_FILE)) != NULL)
	{
		_fparse(fbuf, 0, add_groups_d);
	}
	else
	{
		printf("error reading '" GROUP_FILE "' file\n");
		(passwd_d != NULL) ? free_passwd_d() : 0;
		exit(1);
	}
	free(fbuf);

	display_matrix_d();

	free_passwd_d();
	free_groups_d();
	return 0;
}

void display_matrix_d()
{
	printf(" ");
	for(int head = 0; head < group_c; head++)
	{
		printf(",%s", group_d[head].name);
	}
	printf("\n");
	for(int row = 0; row < passwd_c; row++)
	{
		printf("%s", passwd_d[row].username);
		for(int col = 0; col < group_c; col++)
		{
			char result = is_in_group(row, col);
			printf(",%c", result);
		}
		printf("\n");
	}
}

char is_in_group(int user, int group)
{
	/* is this own user's group? */
	if(strcmp(passwd_d[user].username, group_d[group].name) == 0)
	{
		return 'o';
	}

	/* search the user in other groups */
	char *members = group_d[group].members;
	char *next_member = group_d[group].members;
	char *member = NULL;
	// int member_l = 0;
	char result = '-';

	while(next_member != NULL)
	{
		next_member = _strstr(members, &member, ',');
		// member_l = strlen(member);
		if(strcmp(member, passwd_d[user].username) == 0)
		{
			result = 'm';
			free(member);
			break;
		}
		members = next_member;
		free(member);
	}

	return result;
}

void free_groups_d()
{
	for(int i = 0; i < group_c; i++)
	{
		(group_d[i].name != NULL) ? free(group_d[i].name) : 0;
		(group_d[i].password != NULL) ? free(group_d[i].password) : 0;
		(group_d[i].members != NULL) ? free(group_d[i].members) : 0;
	}
	free(group_d);
}

/* When it returns the false 'groups_d' must be erased manually: call the 'free_groups_d()' */
_Bool add_groups_d(char *buffer)
{
	_Bool result = false;
	if(buffer[0] == '#')
	{
		return result;
	}
	if(buffer == NULL)
	{
		return result;
	}
	char *pbuffer = buffer;
	char *substr = NULL;
	int substr_l = 0;
	if((group_d = (group_t*)realloc(group_d, (sizeof(group_t) * (group_c + 1)))) == NULL)
	{
		return result;
	}

	/* group name */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((group_d[group_c].name = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(group_d[group_c].name, substr, substr_l);
	group_d[group_c].name[substr_l] = 0;
	free(substr);

	/* password */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((group_d[group_c].password = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(group_d[group_c].password, substr, substr_l);
	group_d[group_c].password[substr_l] = 0;
	free(substr);

	/* gid */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	int gid_ = 0;
	if(sscanf(substr, "%d", &gid_) != 1)
	{
		return result;
	}
	group_d[group_c].gid = gid_;
	free(substr);

	/* members */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((group_d[group_c].members = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(group_d[group_c].members, substr, substr_l);
	group_d[group_c].members[substr_l] = 0;
	free(substr);

	group_c++;
	result = true;

	return result;
}

void free_passwd_d()
{
	for(int i = 0; i < passwd_c; i++)
	{
		(passwd_d[i].username != NULL) ? free(passwd_d[i].username) : 0;
		(passwd_d[i].password != NULL) ? free(passwd_d[i].password) : 0;
		(passwd_d[i].personal_data != NULL) ? free(passwd_d[i].personal_data) : 0;
		(passwd_d[i].homedir != NULL) ? free(passwd_d[i].homedir) : 0;
		(passwd_d[i].shell != NULL) ? free(passwd_d[i].shell) : 0;
	}
	free(passwd_d);
}

/* When it returns the false 'passwd_d' must be erased manually: call the 'free_passwd_d()' */
_Bool add_passwd_d(char *buffer)
{
	_Bool result = false;
	if(buffer[0] == '#')
	{
		return result;
	}
	if(buffer == NULL)
	{
		return result;
	}
	char *pbuffer = buffer;
	char *substr = NULL;
	int substr_l = 0;
	if((passwd_d = (passwd_t*)realloc(passwd_d, (sizeof(passwd_t) * (passwd_c + 1)))) == NULL)
	{
		return result;
	}

	/* username */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((passwd_d[passwd_c].username = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(passwd_d[passwd_c].username, substr, substr_l);
	passwd_d[passwd_c].username[substr_l] = 0;
	free(substr);

	/* password */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((passwd_d[passwd_c].password = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(passwd_d[passwd_c].password, substr, substr_l);
	passwd_d[passwd_c].password[substr_l] = 0;
	free(substr);

	/* uid */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	int uid_ = 0;
	if(sscanf(substr, "%d", &uid_) != 1)
	{
		return result;
	}
	passwd_d[passwd_c].uid = uid_;
	free(substr);

	/* gid */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	int gid_ = 0;
	if(sscanf(substr, "%d", &gid_) != 1)
	{
		return result;
	}
	passwd_d[passwd_c].gid = gid_;
	free(substr);

	/* personal data */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((passwd_d[passwd_c].personal_data = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(passwd_d[passwd_c].personal_data, substr, substr_l);
	passwd_d[passwd_c].personal_data[substr_l] = 0;
	free(substr);

	/* homedir */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((passwd_d[passwd_c].homedir = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(passwd_d[passwd_c].homedir, substr, substr_l);
	passwd_d[passwd_c].homedir[substr_l] = 0;
	free(substr);

	/* shell */
	pbuffer = _strstr(pbuffer, &substr, ':');
	substr_l = strlen(substr);
	if((passwd_d[passwd_c].shell = (char*)malloc((substr_l * sizeof(char)) + 1)) == NULL)
	{
		return result;
	}
	memcpy(passwd_d[passwd_c].shell, substr, substr_l);
	passwd_d[passwd_c].shell[substr_l] = 0;
	free(substr);

	passwd_c++;
	result = true;

	return result;
}

char *_strstr(char *instr, char **substr, char splitter)
{
	char *p = NULL;
	int substr_len = 0;
	// int next_value = 0;
	if((p = strchr(instr, splitter)) != NULL)
	{
		substr_len = p - instr;
		// next_value = 1;
	}
	else
	{
		substr_len = strchr(instr, 0) - instr;
		// next_value = 2;
	}
	*substr = (char*)malloc((sizeof(char) * substr_len) + 1);
	memcpy(*substr, instr, substr_len);
	(*substr)[substr_len] = 0;
	(p != NULL) ? (p = p + 1) : (p = NULL);
	return p;
}

int _fparse(char *buf, char splitter, _Bool (*handler)(char*))
{
	int count = 0;
	// int idx = 0;
	if(buf != NULL)
	{
		(splitter == 0) ? (splitter = '\n') : splitter;
		int end = 0;
		int begin = 0;
		while(buf[end] != 0)
		{
			if( (buf[end] == splitter) || (buf[end+1] == 0) )
			{
				int len = end - begin;
				(begin == 0) ? begin : begin++;
				char *str = (char*)malloc( (len * sizeof(char)) + 2 );
				(buf[end+1] == 0) ? len++ : len;
				memcpy(str, &buf[begin], len);
				(str[len-1] == 10) ? str[len-1] = 0 : 0;
				str[len] = 0;
				// Default action - display string to the screen
				if(handler == NULL)
				{
					int i = 0;
					while(str[i] != 0)
					{
						putchar(str[i]);
						i++;
					}
					printf("\n");
					count++;
				}
				else
				{
					(handler(str) == true) ? count++ : count ;
				}
				begin = end;
				free(str);
			}
			end++;
		}
	}
	return count;
}

char* _fread(char *fn)
{
	char *fb = NULL;
	if(fn != NULL)
	{
		FILE *fd = fopen(fn, "rb");
		if(fd != NULL)
		{
			if(fseek(fd, 0, SEEK_END) == 0)
			{
				long fs = ftell(fd);
				if(fs != -1)
				{
					rewind(fd);
					fb = (char*) malloc((sizeof(char) * fs) + 1);
					if(fb != NULL)
					{
						long b = fread(fb, 1, fs, fd);
						(b != -1) ? (fb[b] = 0) : free(fb);
					}
				}
			}
			_fclose(fd);
		}
	}
	return fb;
}

_Bool _fclose(FILE *fd)
{
	if(fd != NULL)
	{
		if(fclose(fd) == 0)
		{
			return true;
		}
	}
	return false;
}
