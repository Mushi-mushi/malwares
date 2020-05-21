/* Sniffit Interface File -- Brecht Claerhout                               */

/*** Sreen operations */
void init_screen (void)
{
	initscr();
	cbreak();
	noecho();
	nonl();
	clear();
	if(has_colors()!=-1)	
		{
  		COLOR_AVAIL=1;
  		start_color();
  		init_pair(WIN_COLOR_NORMAL,COLOR_WHITE,COLOR_BLUE);
  		init_pair(WIN_COLOR_POINT,COLOR_BLUE,COLOR_CYAN);
  		init_pair(WIN_COLOR_DATA,COLOR_BLUE,COLOR_CYAN);
  		init_pair(WIN_COLOR_INPUT,COLOR_BLUE,COLOR_CYAN);
  		init_pair(WIN_COLOR_MENU,COLOR_BLUE,COLOR_CYAN);
  		};
};

void box_window (struct box_window *Win, 
                 int num_lines, int num_cols, int begy,int begx) 
{
	int i;

	Win->main_window=newwin(num_lines,num_cols,begy,begx);
	Win->work_window=subwin(Win->main_window,num_lines-2,
					num_cols-2,begy+1,begx+1);
	if(COLOR_AVAIL)	
		{
  		wattrset(Win->main_window,COLOR_PAIR(WIN_COLOR_NORMAL));
  		wattrset(Win->work_window,COLOR_PAIR(WIN_COLOR_NORMAL));
  		for(i=0;i<=(num_lines-2);i++)
			whline(Win->work_window,' ',num_cols-2);
  		}
	keypad(Win->work_window,1);
	box(Win->main_window,ACS_VLINE,ACS_HLINE);
	mvwprintw(Win->main_window,0,3,"Sniffit %s",VERSION);
	wmove(Win->work_window,0,0);
	wnoutrefresh(Win->main_window);wnoutrefresh(Win->work_window);
	doupdate();
}

void data_window (struct box_window *Win, struct box_window *P_Win,
                 int num_lines, int num_cols, int begy,int begx,
                 char *buffer, int listitem) 
{
	int i=0;

	while(i<listitem)
  		if(*(buffer+(i*CONN_NAMELEN))!=0)
    			i++;
	Win->main_window=newwin(num_lines,num_cols,begy,begx);
	Win->work_window=subwin(Win->main_window,num_lines-5,num_cols-2,begy+1,begx+1);
	scrollok(Win->work_window,1);
	if(COLOR_AVAIL)	
  		wattrset(Win->main_window,COLOR_PAIR(WIN_COLOR_DATA));

	box(Win->main_window,ACS_VLINE,ACS_HLINE);
	wmove(Win->main_window,num_lines-3,1);
	whline(Win->main_window,ACS_HLINE,num_cols-2);
	wmove(Win->main_window,num_lines-2,1);
	whline(Win->main_window,' ',num_cols-2);
	wmove(Win->main_window,num_lines-2,2);
	waddstr(Win->main_window, (buffer+(i*CONN_NAMELEN)));
	strcpy(logged_connection,(buffer+(i*CONN_NAMELEN)));
	wmove(Win->work_window,0,0);
	wnoutrefresh(Win->main_window);wnoutrefresh(Win->work_window);
	doupdate();
}

void data_device (char *buffer, int listitem) 
{
	int i=0;

	while(i<listitem)
  		if(*(buffer+(i*CONN_NAMELEN))!=0)
    			i++;
	strcpy(logged_connection,(buffer+(i*CONN_NAMELEN)));
}

void mask_status (struct box_window *Work_win)
{
	unsigned char *ad;
	int i;

	wmove(Work_win->work_window,0,1);
	for(i=0;i<2;i++)
		{wmove(Work_win->work_window,i,0);
		whline(Work_win->work_window,' ',COLS-2);}
	wmove(Work_win->work_window,0,1);
	wprintw(Work_win->work_window,"Source IP     : ");
	ad=&(mask->source_ip);
	if(mask->source_ip==0)
  		wprintw(Work_win->work_window,"All");
	else wprintw(Work_win->work_window,"%u.%u.%u.%u",
					ad[0],ad[1],ad[2],ad[3]);
	wmove(Work_win->work_window,1,1);
	wprintw(Work_win->work_window,"Destination IP: ");
	ad=&(mask->destination_ip);
	if(mask->destination_ip==0)
  		wprintw(Work_win->work_window,"All");
	else wprintw(Work_win->work_window,"%u.%u.%u.%u",
					ad[0],ad[1],ad[2],ad[3]);
	wmove(Work_win->work_window,0,35);
	wprintw(Work_win->work_window,"Source PORT     : ");
	if(mask->source_port==0)
  		wprintw(Work_win->work_window,"All");
	else wprintw(Work_win->work_window,"%u",mask->source_port);
	wmove(Work_win->work_window,1,35);
	wprintw(Work_win->work_window,"Destination PORT: ");
	if(mask->destination_port==0)
  		wprintw(Work_win->work_window,"All");
	else wprintw(Work_win->work_window,"%u",mask->destination_port);
	wnoutrefresh(Work_win->main_window);
	wnoutrefresh(Work_win->work_window);
	doupdate();
}

void fill_box_window (struct box_window *Work_win, char *buffer, 
                      int begin_item, int boxlen, int rowlen)
                                                 /* 0 is the first item  */
{
	int i=0, j=0, line=0;

	while(i<begin_item)
  		if(*(buffer+(i*CONN_NAMELEN))!=0)
    			i++;

	while((line<boxlen)&& ((i+j)<CONNECTION_CAPACITY) )	
		{
  		if(*(buffer+((i+j)*CONN_NAMELEN) ) != 0)	
			{
			wmove(Work_win->work_window,line,0);
			whline(Work_win->work_window,' ',rowlen);
			if(strcmp(logged_connection,
					(buffer+((i+j)*CONN_NAMELEN))) != 0) 
    				wprintw(Work_win->work_window," %s",
						(buffer+((i+j)*CONN_NAMELEN)));
			else
    				wprintw(Work_win->work_window,
					        " %s           *LOGGED*",
						(buffer+((i+j)*CONN_NAMELEN)));

    			line++;
    			}
  		j++;
  		}
	for(i=line;i<boxlen;i++)	
		{
  		wmove(Work_win->work_window,i,0);
		whline(Work_win->work_window,' ',rowlen);
  		};
	wnoutrefresh(Work_win->work_window);
}

void point_item (struct box_window *Work_win, char *buffer, 
                 int item, int begin_item, int boxlen, int rowlen)
{
	int i=0,j;

	while(i<item)
  		if(*(buffer+(i*CONN_NAMELEN))!= 0)
    			i++;

	if(*(buffer+(i*CONN_NAMELEN))!=0)	
		{
  		wattrset(Work_win->work_window,COLOR_PAIR(WIN_COLOR_POINT));
  		wmove(Work_win->work_window,item-begin_item,0);
		whline(Work_win->work_window,' ',rowlen);

		if(strcmp(logged_connection,(buffer+(i*CONN_NAMELEN)))!=0)
  			mvwprintw(Work_win->work_window,item-begin_item,0,
						" %s",
                                             	(buffer+(i*CONN_NAMELEN)) );
		else
    			mvwprintw(Work_win->work_window,item-begin_item,0,
					        " %s           *LOGGED*",
                                             	(buffer+(i*CONN_NAMELEN)) );
  
		wnoutrefresh(Work_win->work_window);
  		wattrset(Work_win->work_window,COLOR_PAIR(WIN_COLOR_NORMAL));
  		}
}

void forced_refresh (void)	
{
	fill_box_window(&main_box, running_connections,LISTpos,18,COLS-2);
	point_item(&main_box, running_connections, POINTpos,LISTpos,18,COLS-2);
	if((LOGGING==1)&&(logging_device==NULL))	
		{
		touchwin(data_box.main_window);touchwin(data_box.work_window);
   		wnoutrefresh(data_box.main_window);wnoutrefresh(data_box.work_window);
   		}
	doupdate();
}

void menu_line (void)
{
	int i;

	if(menu_window==NULL)
  		menu_window=newwin (1,COLS,LINES-1,0);
	if(COLOR_AVAIL!=0)	
		{
		wattrset(menu_window,COLOR_PAIR(WIN_COLOR_MENU));
		wmove(menu_window,0,0);
		whline(menu_window,' ',COLS);
		}
	mvwaddstr(menu_window,0,0,MENU);
	wnoutrefresh(menu_window);
}

char *input_field(char *string, char *input)
{
	int i;
	WINDOW *Work_txt, *Work_inp;

	Work_txt=newwin(1,COLS,LINES-1,0);
	Work_inp=newwin(1,50,LINES-1,strlen(string));
	if(COLOR_AVAIL!=0)
  		{
		wattrset(Work_inp,COLOR_PAIR(WIN_COLOR_INPUT));
  		wattrset(Work_txt,COLOR_PAIR(WIN_COLOR_NORMAL));
		whline(Work_txt,' ',COLS);
		whline(Work_inp,' ',50);
		}
	mvwaddstr(Work_txt,0,0,string);
	wnoutrefresh(Work_txt);wnoutrefresh(Work_inp);
	doupdate();
	echo();mvwgetstr(Work_inp,0,0,input);noecho();
	delwin(Work_inp);delwin(Work_txt);
	menu_line();
	forced_refresh();
	return input;
}

void exec_mask (void)
{
	clear_shared_mem(1);
	mask_status(&mask_box);
	forced_refresh();
}

/* siganling */

void sig_blocking(char on_off)
{
	sigset_t set;

	sigemptyset(&set);sigaddset(&set,SIGUSR1);
if(on_off==1)
	sigprocmask(SIG_BLOCK,&set,NULL);
else	{sigprocmask(SIG_UNBLOCK,&set,NULL);}
}

void set_signal (int signum, sig_hand new_action)
{	
	struct sigaction new_sigusr;
	sigset_t sig_mask;

	sigemptyset(&sig_mask);
	sigaddset(&sig_mask,signum);
	new_sigusr.sa_handler=new_action;
	new_sigusr.sa_mask=sig_mask;
	new_sigusr.sa_flags=0;
	sigaction(signum,&new_sigusr,NULL);
}

void interaction (int sig)
{
	int i;
	if((LOGGING==1)&&(*logged_connection==0)) stop_logging();
	if((LOGGING==1)&&(*DATAlength!=0))
  		{
		if(logging_device==NULL)
			{
	  		for(i=0;i<*DATAlength;i++)
    				waddch(data_box.work_window,
    				isprint(*(connection_data+i))?
						*(connection_data+i):'.');
			}
		else	{
	  		for(i=0;i<*DATAlength;i++)
    				fputc(*(connection_data+i),log_dev_stream);
			fflush(log_dev_stream);
			}
  		*DATAlength=0;
  		}
	forced_refresh();
	set_signal(SIGUSR1,interaction); 
}

/* atexit's */

void child_exit (void)
{
	kill(Pid,SIGKILL);
};

void screen_exit (void)
{
	clear();
	endwin();
};

void mem_exit (void)
{
	if(shmctl(memory_id,IPC_RMID,0)<0)
  		{perror("Sniffer Hartattack (you are fucked!) ");exit(0);};
}

/* Some other stuff */

void stop_logging (void)
{	
	LOGGING=0;
	*logged_connection=0;
	if(logging_device==NULL)
		delwin(data_box.work_window), delwin(data_box.main_window);
}

int add_itemlist(char *buffer, char *string)
{
int i;

	for(i=0;i<CONNECTION_CAPACITY;i++)
  	if(strcmp( (buffer+(i*CONN_NAMELEN)), string)==0)
			return -1;

	for(i=0;i<CONNECTION_CAPACITY;i++)
  		if(*(buffer+(i*CONN_NAMELEN))==0)
    			{
			strcpy((char *)(buffer+(i*CONN_NAMELEN)), string);
    			(*LISTlength)++;return i;
    			}
	return -1;
}

int del_itemlist(char *buffer, char *string)
{
	int i;

	if(strcmp( logged_connection, string)==0)
  		*logged_connection=0;
	for(i=0;i<CONNECTION_CAPACITY;i++)
  		if(strcmp( (buffer+(i*CONN_NAMELEN)), string)==0)
    			{
			*(buffer+(i*CONN_NAMELEN))=0; 
    			(*LISTlength)--;return i;
    			}
	return -1;
}

void clear_shared_mem(char mode) 
			/* mode = 0    all       */
			/* mode = 1    keep mask */
{
	int i;

	*timing=1;
	*DATAlength=0;
	*LISTlength=-1;
	if(mode==0)
		mask->source_ip=mask->destination_ip=
			mask->source_port=mask->destination_port=0;
	*logged_connection=0;
	for(i=0;i<CONNECTION_CAPACITY;i++)
  		*(running_connections+(i*CONN_NAMELEN))=0;
	*timing=0;
};

/*** Main interface program */

void run_interface(void)
{
	int i,key_hit;
	char dummy[50];

	set_signal(SIGUSR1,interaction);
	init_screen();	        	/* The whole screen setup */
	atexit(screen_exit);
	box_window(&mask_box,4,COLS,20,0);
	mask_status(&mask_box);
	box_window(&main_box,20,COLS,0,0);
	fill_box_window(&main_box, running_connections,LISTpos,18,COLS-2);
	point_item(&main_box, running_connections,POINTpos,LISTpos,18,COLS-2);
	menu_window=NULL;
	menu_line();
	doupdate();                      /* And..... draw it! */

	while(1)
  		{
  		if((POINTpos>*LISTlength)&&(*LISTlength>=0)) POINTpos=*LISTlength;
 		key_hit=wgetch(main_box.work_window);
		sig_blocking(1);
 		switch(key_hit)
    			{
    			case KEY_DOWN:
       				if(POINTpos>=*LISTlength) break;
       				if(POINTpos<(LISTpos+17))
         				POINTpos++;
      				else
         				{if(LISTpos>=*LISTlength) break; 
					LISTpos++; POINTpos++;};
				forced_refresh();
       				break;
    			case KEY_UP:
       				if(POINTpos==0) break;
       				if(POINTpos>LISTpos)
         				POINTpos--;
       				else
         				{if(LISTpos==0) break; 
					LISTpos--; POINTpos--;};
				forced_refresh();
       				break;
    			case ENTER:
       				if(*LISTlength<0) break;
       				if(LOGGING==0)
        				{
         				if(logging_device==NULL)
					  data_window(&data_box,&main_box,
						10,COLS-10,5,5,
						running_connections,POINTpos);
					else 
					  data_device(running_connections,
								POINTpos);
        			 	LOGGING=1;
         				}
      			 	else
         				{
         				stop_logging();
         				if(logging_device==NULL)
					  data_window(&data_box,&main_box,
						10,COLS-10,5,5,
						running_connections,POINTpos);
					else 
					  data_device(running_connections,
								POINTpos);
				         LOGGING=1;
         				 };
       				break;
    			case KEY_F(10):
       				if(LOGGING==1)
          				{stop_logging();
           				forced_refresh();}
       				else
					{kill(Pid,SIGKILL);exit(0);}
				break;

			case KEY_F(1):
       				input_field("Source Ip: ",dummy); 
				mask->source_ip=getaddrbyname(dummy);
				exec_mask();
				break;
    			case KEY_F(2):
       				input_field("Destination Ip: ",dummy);
				mask->destination_ip=getaddrbyname(dummy);
				exec_mask();
       				break;
    			case KEY_F(3):
       				input_field("Source Port: ",dummy);
                                mask->source_port=atoi(dummy);
				exec_mask();
      			 	break;
    			case KEY_F(4):
       				input_field("Destination Port: ",dummy);
                                mask->destination_port=atoi(dummy);
				exec_mask();
       				break;
    			default: break;
    			}
		sig_blocking(0);
  		}
};

