/* sim-safe.c - sample functional simulator implementation */

/* SimpleScalar(TM) Tool Suite
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 * All Rights Reserved. 
 * 
 * THIS IS A LEGAL DOCUMENT, BY USING SIMPLESCALAR,
 * YOU ARE AGREEING TO THESE TERMS AND CONDITIONS.
 * 
 * No portion of this work may be used by any commercial entity, or for any
 * commercial purpose, without the prior, written permission of SimpleScalar,
 * LLC (info@simplescalar.com). Nonprofit and noncommercial use is permitted
 * as described below.
 * 
 * 1. SimpleScalar is provided AS IS, with no warranty of any kind, express
 * or implied. The user of the program accepts full responsibility for the
 * application of the program and the use of any results.
 * 
 * 2. Nonprofit and noncommercial use is encouraged. SimpleScalar may be
 * downloaded, compiled, executed, copied, and modified solely for nonprofit,
 * educational, noncommercial research, and noncommercial scholarship
 * purposes provided that this notice in its entirety accompanies all copies.
 * Copies of the modified software can be delivered to persons who use it
 * solely for nonprofit, educational, noncommercial research, and
 * noncommercial scholarship purposes provided that this notice in its
 * entirety accompanies all copies.
 * 
 * 3. ALL COMMERCIAL USE, AND ALL USE BY FOR PROFIT ENTITIES, IS EXPRESSLY
 * PROHIBITED WITHOUT A LICENSE FROM SIMPLESCALAR, LLC (info@simplescalar.com).
 * 
 * 4. No nonprofit user may place any restrictions on the use of this software,
 * including as modified by the user, by any other authorized user.
 * 
 * 5. Noncommercial and nonprofit users may distribute copies of SimpleScalar
 * in compiled or executable form as set forth in Section 2, provided that
 * either: (A) it is accompanied by the corresponding machine-readable source
 * code, or (B) it is accompanied by a written offer, with no time limit, to
 * give anyone a machine-readable copy of the corresponding source code in
 * return for reimbursement of the cost of distribution. This written offer
 * must permit verbatim duplication by anyone, or (C) it is distributed by
 * someone who received only the executable form, and is accompanied by a
 * copy of the written offer of source code.
 * 
 * 6. SimpleScalar was developed by Todd M. Austin, Ph.D. The tool suite is
 * currently maintained by SimpleScalar LLC (info@simplescalar.com). US Mail:
 * 2395 Timbercrest Court, Ann Arbor, MI 48105.
 * 
 * Copyright (C) 1994-2003 by Todd M. Austin, Ph.D. and SimpleScalar, LLC.
 */


#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "host.h"
#include "misc.h"
#include "machine.h"
#include "regs.h"
#include "memory.h"
#include "loader.h"
#include "syscall.h"
#include "options.h"
#include "stats.h"
#include "sim.h"
/*q2*/
//max bit width of data
#define BIT_MAX 32
/*q3*/
//max reg number
#define REG_NUM_MAX 32
/*
 * This file implements a functional simulator.  This functional simulator is
 * the simplest, most user-friendly simulator in the simplescalar tool set.
 * Unlike sim-fast, this functional simulator checks for all instruction
 * errors, and the implementation is crafted for clarity rather than speed.
 */

/*q1*/
static counter_t g_total_cond_branches;

static counter_t g_total_uncond_branches;

static counter_t g_total_floating_point_insn;

static counter_t g_total_store_insn;

static counter_t g_total_load_insn;

static counter_t g_total_imm_operands;

/*q2*/
static int q2_histogram[BIT_MAX];
static int total_cond;
/* simulated registers */
static struct regs_t regs;

/*q3*/
static int regs_old[REG_NUM_MAX];//store last reg's old value
static int total_reg_bit_changed=0;
static int total_reg_bit_changed_count=0;
static counter_t g_total_bit_changed;
static counter_t g_total_bit_changed_insn;


static int xor_bit_changed=0;


/* simulated memory */
static struct mem_t *mem = NULL;

/* track number of refs */
static counter_t sim_num_refs = 0;

/* maximum number of inst's to execute */
static unsigned int max_insts;

/* register simulator-specific options */
void
sim_reg_options(struct opt_odb_t *odb)
{
  opt_reg_header(odb, 
"sim-safe: This simulator implements a functional simulator.  This\n"
"functional simulator is the simplest, most user-friendly simulator in the\n"
"simplescalar tool set.  Unlike sim-fast, this functional simulator checks\n"
"for all instruction errors, and the implementation is crafted for clarity\n"
"rather than speed.\n"
		 );

  /* instruction limit */
  opt_reg_uint(odb, "-max:inst", "maximum number of inst's to execute",
	       &max_insts, /* default */0,
	       /* print */TRUE, /* format */NULL);

}

/* check simulator-specific option values */
void
sim_check_options(struct opt_odb_t *odb, int argc, char **argv)
{
  /* nada */
}

/* register simulator-specific statistics */
void
sim_reg_stats(struct stat_sdb_t *sdb)
{
  stat_reg_counter(sdb, "sim_num_insn",
		   "total number of instructions executed",
		   &sim_num_insn, sim_num_insn, NULL);
  stat_reg_counter(sdb, "sim_num_refs",
		   "total number of loads and stores executed",
		   &sim_num_refs, 0, NULL);
  stat_reg_int(sdb, "sim_elapsed_time",
	       "total simulation time in seconds",
	       &sim_elapsed_time, 0, NULL);
  stat_reg_formula(sdb, "sim_inst_rate",
		   "simulation speed (in insts/sec)",
		   "sim_num_insn / sim_elapsed_time", NULL);
  /*q1*/
  stat_reg_counter(sdb, "sim_num_cond_branches",
		"total conditional branches executed",
		&g_total_cond_branches, 0, NULL);
  stat_reg_formula(sdb, "sim_cond_branch_freq",
  		"relative frequency of conditional branches",
  		"sim_num_cond_branches/ sim_num_insn", NULL);
  
  stat_reg_counter(sdb,"sim_num_uncond_branches",
		  "total uncondition branches executed",
		  &g_total_uncond_branches, 0, NULL);
  stat_reg_formula(sdb,"sim_uncond_branch_freq",
		  "relative frequency of uncondition branches",
		  "sim_num_uncond_branches/sim_num_insn", NULL);

  stat_reg_counter(sdb,"sim_num_floating_point_insn",
		  "total floating point instructions executed",
		  &g_total_floating_point_insn, 0, NULL);
  stat_reg_formula(sdb,"sim_floating_point_insn_freq",
		  "relative frequency of floating point instructions",
		  "sim_num_floating_point_insn/sim_num_insn", NULL);

  stat_reg_counter(sdb,"sim_num_store_insn",
		  "total store instructions executed",
		  &g_total_store_insn, 0, NULL);
  stat_reg_formula(sdb,"sim_store_insn_freq",
		  "relative frequency of store instructions",
		  "sim_num_store_insn/sim_num_insn", NULL);

  stat_reg_counter(sdb,"sim_num_load_insn",
		  "total load instructions executed",
		  &g_total_load_insn, 0, NULL);
  stat_reg_formula(sdb,"sim_load_insn_freq",
		  "relative frequency of load instructions",
		  "sim_num_load_insn/sim_num_insn", NULL);

  stat_reg_counter(sdb,"sim_num_imm_operands",
		  "total immediate operands executed",
		  &g_total_imm_operands, 0, NULL);
  stat_reg_formula(sdb,"sim_immed_operand_freq",
		  "relative frequency of immediate operands",
		  "sim_num_imm_operands/sim_num_insn", NULL);
  /*q3*/
  stat_reg_counter(sdb,"sim_num_total_bit_changed",
		  "total bit changed",
		  &g_total_bit_changed, 0, NULL);

  stat_reg_counter(sdb,"sim_num_total_bit_changed_insn",
		  "total bit changed insn executed",
		  &g_total_bit_changed_insn, 0, NULL);

  stat_reg_formula(sdb,"bit_changed_freq",
		  "bit changed per bit change insn",
		  "sim_num_total_bit_changed/sim_num_total_bit_changed_insn", NULL);
  ld_reg_stats(sdb);
  mem_reg_stats(mem, sdb);
}

/* initialize the simulator */
void
sim_init(void)
{
  sim_num_refs = 0;

  /* allocate and initialize register file */
  regs_init(&regs);

  /* allocate and initialize memory space */
  mem = mem_create("mem");
  mem_init(mem);
}

/* load program into simulated state */
void
sim_load_prog(char *fname,		/* program to load */
	      int argc, char **argv,	/* program arguments */
	      char **envp)		/* program environment */
{
  /* load program text and data, set up environment, memory, and regs */
  ld_load_prog(fname, argc, argv, envp, &regs, mem, TRUE);
}

/* print simulator-specific configuration information */
void
sim_aux_config(FILE *stream)		/* output stream */
{
  /* nothing currently */
  

}

/* dump simulator-specific auxiliary simulator statistics */
void
sim_aux_stats(FILE *stream)		/* output stream */
{

  FILE *data;
  data=fopen("q2data.txt","w"); 
  int i;  
  for(i=0;i<BIT_MAX;++i){
    fprintf(data,"\n%.2f",(float)(q2_histogram[i])/(float)(total_cond/100));
    printf("\n%d bit %.2f",i+1,(float)(q2_histogram[i])/(float)(total_cond/100));
  }
  fclose(data);
  
  
}

/* un-initialize simulator-specific state */
void
sim_uninit(void)
{
  /* nada */
}


/*
 * configure the execution engine
 */

/*
 * precise architected register accessors
 */

/* next program counter */
#define SET_NPC(EXPR)		(regs.regs_NPC = (EXPR))

/* current program counter */
#define CPC			(regs.regs_PC)

/* general purpose registers */
#define GPR(N)			(regs.regs_R[N])
#define SET_GPR(N,EXPR)		(regs.regs_R[N] = (EXPR))

#if defined(TARGET_PISA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_L(N)		(regs.regs_F.l[(N)])
#define SET_FPR_L(N,EXPR)	(regs.regs_F.l[(N)] = (EXPR))
#define FPR_F(N)		(regs.regs_F.f[(N)])
#define SET_FPR_F(N,EXPR)	(regs.regs_F.f[(N)] = (EXPR))
#define FPR_D(N)		(regs.regs_F.d[(N) >> 1])
#define SET_FPR_D(N,EXPR)	(regs.regs_F.d[(N) >> 1] = (EXPR))

/* miscellaneous register accessors */
#define SET_HI(EXPR)		(regs.regs_C.hi = (EXPR))
#define HI			(regs.regs_C.hi)
#define SET_LO(EXPR)		(regs.regs_C.lo = (EXPR))
#define LO			(regs.regs_C.lo)
#define FCC			(regs.regs_C.fcc)
#define SET_FCC(EXPR)		(regs.regs_C.fcc = (EXPR))

#elif defined(TARGET_ALPHA)

/* floating point registers, L->word, F->single-prec, D->double-prec */
#define FPR_Q(N)		(regs.regs_F.q[N])
#define SET_FPR_Q(N,EXPR)	(regs.regs_F.q[N] = (EXPR))
#define FPR(N)			(regs.regs_F.d[(N)])
#define SET_FPR(N,EXPR)		(regs.regs_F.d[(N)] = (EXPR))

/* miscellaneous register accessors */
#define FPCR			(regs.regs_C.fpcr)
#define SET_FPCR(EXPR)		(regs.regs_C.fpcr = (EXPR))
#define UNIQ			(regs.regs_C.uniq)
#define SET_UNIQ(EXPR)		(regs.regs_C.uniq = (EXPR))

#else
#error No ISA target defined...
#endif

/* precise architected memory state accessor macros */
#define READ_BYTE(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_BYTE(mem, addr))
#define READ_HALF(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_HALF(mem, addr))
#define READ_WORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_WORD(mem, addr))
#ifdef HOST_HAS_QWORD
#define READ_QWORD(SRC, FAULT)						\
  ((FAULT) = md_fault_none, addr = (SRC), MEM_READ_QWORD(mem, addr))
#endif /* HOST_HAS_QWORD */

#define WRITE_BYTE(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_BYTE(mem, addr, (SRC)))
#define WRITE_HALF(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_HALF(mem, addr, (SRC)))
#define WRITE_WORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_WORD(mem, addr, (SRC)))
#ifdef HOST_HAS_QWORD
#define WRITE_QWORD(SRC, DST, FAULT)					\
  ((FAULT) = md_fault_none, addr = (DST), MEM_WRITE_QWORD(mem, addr, (SRC)))
#endif /* HOST_HAS_QWORD */

/* system call handler macro */
#define SYSCALL(INST)	sys_syscall(&regs, mem_access, mem, INST, TRUE)

#define DNA         (-1)

/* general register dependence decoders */
#define DGPR(N)         (N)
#define DGPR_D(N)       ((N) &~1)

/* floating point register dependence decoders */
#define DFPR_L(N)       (((N)+32)&~1)
#define DFPR_F(N)       (((N)+32)&~1)
#define DFPR_D(N)       (((N)+32)&~1)

/* miscellaneous register dependence decoders */
#define DHI         (0+32+32)
#define DLO         (1+32+32)
#define DFCC            (2+32+32)
#define DTMP            (3+32+32)

/* start simulation, program loaded, processor precise state initialized */
void
sim_main(void)
{
  md_inst_t inst;
  register md_addr_t addr;
  enum md_opcode op;
  register int is_write;
  enum md_fault_type fault;

  /*q2*/
  int offset_shift,offset_needs_bits,offset;
  /*q3*/
  int dst_reg;
  int reg_old,reg_new;
  int bit_check;

  fprintf(stderr, "sim: ** starting functional simulation **\n");

  /* set up initial default next PC */
  regs.regs_NPC = regs.regs_PC + sizeof(md_inst_t);


  while (TRUE)
    {
      /* maintain $r0 semantics */
      regs.regs_R[MD_REG_ZERO] = 0;
#ifdef TARGET_ALPHA
      regs.regs_F.d[MD_REG_ZERO] = 0.0;
#endif /* TARGET_ALPHA */

      /* get the next instruction to execute */
      MD_FETCH_INST(inst, mem, regs.regs_PC);

      /* keep an instruction count */
      sim_num_insn++;

      /* set default reference address and access mode */
      addr = 0; is_write = FALSE;

      /* set default fault - none */
      fault = md_fault_none;

      /* decode the instruction */
      MD_SET_OPCODE(op, inst);

      /* execute the instruction */
      switch (op){
#define DEFINST(OP,MSK,NAME,OPFORM,RES,FLAGS,O1,O2,I1,I2,I3)		\
	case OP:							\
	  dst_reg=O1;\
	  if(dst_reg>0 && dst_reg<REG_NUM_MAX){\
	  regs_old[dst_reg]=regs.regs_R[dst_reg];}\
          SYMCAT(OP,_IMPL);						\
          break;
#define DEFLINK(OP,MSK,NAME,MASK,SHIFT)					\
        case OP:							\
          panic("attempted to execute a linking opcode");
#define CONNECT(OP)
#define DECLARE_FAULT(FAULT)						\
	  { fault = (FAULT); break; }
#include "machine.def"
	default:
	  panic("attempted to execute a bogus opcode");
      }
	/*q1*/
	if( MD_OP_FLAGS(op) & F_COND ){
		g_total_cond_branches++;
		total_cond++;
		/*q2*/
		//PC is incremented by 8 for sequential insn
		//we need the number of instructions btw TPC and PC
		if(regs.regs_TPC>=regs.regs_PC){
		    offset=(regs.regs_TPC-regs.regs_PC)/8;
		}
		else{
		    offset=(regs.regs_PC-regs.regs_TPC)/8;
		}
		//32 bit int
		//offset_shift is 31 because only have to shift 31 times to get the value on 32th position 
		offset_shift=31;
		offset_needs_bits=31;
		//need at least one bit even offset=0, so offset_shift checks 32th down to 1st position
		while(offset_shift>0){                     
		    //keep decreasing "offset" until meet the first 1
		    if((offset>>offset_shift)==0){    
		        offset_shift--;
		        offset_needs_bits--;
		    }
		    //break when encounter first 1
		    else{
		        break;
		    }
        	}

		//in 2's compl, nums need an extra 1 in the front
		
		offset_needs_bits++;
		
		//always supposed to be true, add this if case to prevent from unexpected large/small offset 
		if(offset_needs_bits<=31){
		  q2_histogram[offset_needs_bits]++;
		}       
        }  
	if(MD_OP_FLAGS(op)&F_UNCOND){
		g_total_uncond_branches++;
	}

	if(MD_OP_FLAGS(op)&F_STORE){
		g_total_store_insn++;
	}

	if(MD_OP_FLAGS(op)&F_LOAD){
		g_total_load_insn++;
	}

	if(MD_OP_FLAGS(op)&（F_FCOMP|F_FPCOND)){
		g_total_floating_point_insn++;
	}

	if(MD_OP_FLAGS(op)&F_IMM){
		g_total_imm_operands++;
	}

      if (fault != md_fault_none)
	fatal("fault (%d) detected @ 0x%08p", fault, regs.regs_PC);

      if (verbose)
	{
	  myfprintf(stderr, "%10n [xor: 0x%08x] @ 0x%08p: ",
		    sim_num_insn, md_xor_regs(&regs), regs.regs_PC);
	  md_print_insn(inst, regs.regs_PC, stderr);
	  if (MD_OP_FLAGS(op) & F_MEM)
	    myfprintf(stderr, "  mem: 0x%08p", addr);
	  fprintf(stderr, "\n");
	  /* fflush(stderr); */
	}

      if (MD_OP_FLAGS(op) & F_MEM)
	{
	  sim_num_refs++;
	  if (MD_OP_FLAGS(op) & F_STORE)
	    is_write = TRUE;
	}
	/*q3*/
	
	if(dst_reg<REG_NUM_MAX && dst_reg>0){
	
xor_bit_changed=0;
		bit_check=BIT_MAX-1;//31
		reg_old=regs_old[dst_reg];
		reg_new=regs.regs_R[dst_reg];

		xor_bit_changed=reg_new^reg_old;
		if(reg_old!=reg_new){
			while(bit_check>=0){//check by shift 0-31
				if(((reg_old>>bit_check) & 0x01)!=((reg_new>>bit_check) &0x01)){
				  total_reg_bit_changed++;
				  g_total_bit_changed++;
				}
				bit_check--;			
			}
			
		}
		total_reg_bit_changed_count++;
		g_total_bit_changed_insn++;
					
	}


      /* go to the next instruction */
      regs.regs_PC = regs.regs_NPC;
      regs.regs_NPC += sizeof(md_inst_t);

      /* finish early? */
      if (max_insts && sim_num_insn >= max_insts)
	return;
    }
}
