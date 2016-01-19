/*
============================================================================
Name        : graphBinAlgo.c
Author      : Aurelien Thierry
Version     :
Copyright   : Your copyright notice
Description : Tests of algorithms for graph isomorphisms on binary dumps
============================================================================
*/

#include "libGraphBinAlgo.h"

int pcharcmp(char* c1, char* c2, int size){
	char eq=1;
	int i;

	for (i=0; i<size; i++){
		if (c1[i] != c2[i]){
			eq=0;
			break;
		}
	}

	return eq;
}

void* processSubGraphs(void* grData){
	struct structProcessGraph *d = grData;
	graph_t* grPattern=d->grPattern;
	graph_t** vgraphsT=d->graphsToTest;
	size_t debutPattern=d->debutPattern;
	size_t finPattern=d->finPattern;
	size_t tailleTest=d->tailleTest;
	sem_post(&mutexStructRead);

	if (optionDebug) printf("I will process %d tests graphs, taking pattern graphs between %d and %d.\n", tailleTest, debutPattern, finPattern);
	int i;
	int j;
	int isoLocal=0;
	int nSgraphPLocal=0;
	graph_t* vgraphP;
	for (j=debutPattern; j<finPattern; j++){
		if (optionDebug) printf("processing pattern %d\n", j);
		sem_wait(&mutexBSFPattern);
		vgraphP=BFS_gba(grPattern, j, wP);
		sem_post(&mutexBSFPattern);
		if (vgraphP != NULL){
			nSgraphPLocal++;

			for (i=0; i<tailleTest; i++){
				if (optionDebug) printf("Pattern %d against Test %i\n", j, i);
				if (vgraphsT[i] != NULL){
					if (optionDebug){
						printf("\nDEBUG P %d, T %d ", j, i);
					}

					int nbIso=isoUllman(vgraphP, vgraphsT[i]);
					isoLocal+=nbIso;

					if (nbIso != 0){
						if (optionDebug){
							printf("Match");
						}

						if (optionExport){
							sem_wait(&mutexExport);
							// exports T roots
							fprintf(FILEeT, "%x\n", (int) vgraphsT[i]->root->node_id);
							fflush(FILEeT);

							// exports P roots
							fprintf(FILEeP, "%x\n", (int) grPattern->root->node_id);
							fflush(FILEeP);

							// exports all T nodes
							node_list_t* listG = &(vgraphsT[i]->nodes);

							int i;
							for (i=0; i<listG->count; i++){
								node_t* n = node_list_item(listG, i);
								fprintf(FILEenT, "%x ", (int) n->node_id);
							}

							fprintf(FILEenT, "\n");
							fflush(FILEenT);

							// exports all P nodes
							listG = &(vgraphP->nodes);

							for (i=0; i<listG->count; i++){
								node_t* n = node_list_item(listG, i);
								fprintf(FILEenP, "%x ", (int) n->node_id);
							}

							fprintf(FILEenP, "\n");
							fflush(FILEenP);
							sem_post(&mutexExport);
						}

						break;
					}
				}
			}

			if (optionDebug && i==tailleTest && !optionMultiThreaded){
				printf("\nDEBUG P %d No", j);
			}
		}
		graph_free(vgraphP);
	}

	int* tabInt = malloc(2*sizeof(int));
	tabInt[0]=nSgraphPLocal;
	tabInt[1]=isoLocal;
	pthread_exit ((void *) tabInt);
}

void createGraphs(){
	// Creates a graph pattern for tests (simple graph with 3 nodes)
	int nP=3;
	graph_t* grPattern = graph_alloc(nP);

	node_t* nP0=node_list_append(&grPattern->nodes, 0);
	node_t* nP1=node_list_append(&grPattern->nodes, 1);
	node_t* nP2=node_list_append(&grPattern->nodes, 2);
//	node_t* nP3=node_list_append(&grPattern->nodes, 3);

	nP0->symb=8;
	nP1->symb=8;
	nP2->symb=9;

	int i;
	for (i=4; i<nP; i++){
		node_list_append(&grPattern->nodes, i);
	}

	node_link(nP0, nP1);
	node_link(nP0, nP2);
//	node_link(nP2, nP0);

	grPattern->root=nP0;

	// outputs the pattern as .dot
	FILE *fpP;
	fpP = fopen("graphPattern.dot", "w");
	graph_fprint(fpP, grPattern);
	fclose(fpP);

	// outputs the pattern as .graphbin (binary dump)
	FILE *fpPb;
	fpPb = fopen("graphPattern.graphbin", "w");
	graph_to_file(grPattern, fpPb);
	fclose(fpPb);

	graph_free(grPattern);

	// Creates a (simple) graph containing the pattern with 4 nodes
	int nT=10;
	graph_t* grToTest = graph_alloc(nT);

	node_t* nT0=node_list_append(&grToTest->nodes, 0);
	node_t* nT1=node_list_append(&grToTest->nodes, 1);
	node_t* nT2=node_list_append(&grToTest->nodes, 2);
	node_t* nT3=node_list_append(&grToTest->nodes, 3);
	node_t* nT4=node_list_append(&grToTest->nodes, 4);
	node_t* nT5=node_list_append(&grToTest->nodes, 5);
	node_t* nT6=node_list_append(&grToTest->nodes, 6);
	node_t* nT7=node_list_append(&grToTest->nodes, 7);
	node_t* nT8=node_list_append(&grToTest->nodes, 8);
	node_t* nT9=node_list_append(&grToTest->nodes, 9);

	nT0->symb=8;
	nT1->symb=8;
	nT2->symb=8;
	nT3->symb=9;
	nT4->symb=9;
	nT5->symb=8;
	nT6->symb=8;

	for (i=10; i<nT; i++){
		node_list_append(&grToTest->nodes, i);
	}

	node_link(nT0, nT1);
	node_link(nT1, nT2);
	node_link(nT2, nT0);
	node_link(nT1, nT3);
	node_link(nT2, nT3);
	node_link(nT2, nT5);
	node_link(nT2, nT6);
	node_link(nT3, nT5);
	node_link(nT6, nT5);
	node_link(nT6, nT8);
	node_link(nT5, nT9);
	node_link(nT8, nT9);

	grToTest->root=nT1;

	// outputs the test graph as .dot
	FILE *fpT;
	fpT = fopen("graphToTest.dot", "w");
	graph_fprint(fpT, grToTest);
	fclose(fpT);

	// outputs the test graph as .graphbin (binary dump)
	FILE *fpTb;
	fpTb = fopen("graphToTest.graphbin", "w");
	graph_to_file(grToTest, fpTb);
	fclose(fpTb);

	graph_free(grToTest);


	// Creates a (simple) graph for testings with permutations
	int nPermP=7;
	graph_t* grPermP = graph_alloc(nPermP);

	nT0=node_list_append(&grPermP->nodes, 0);
	nT1=node_list_append(&grPermP->nodes, 1);
	nT2=node_list_append(&grPermP->nodes, 2);
	nT3=node_list_append(&grPermP->nodes, 3);
	nT4=node_list_append(&grPermP->nodes, 4);
	nT5=node_list_append(&grPermP->nodes, 5);
	nT6=node_list_append(&grPermP->nodes, 6);

	nT0->symb=8;
	nT1->symb=8;
	nT2->symb=8;
	nT3->symb=9;
	nT4->symb=9;//2
	nT5->symb=9;
	nT6->symb=9;//1

	node_link(nT0, nT1);
	node_link(nT0, nT2);
	node_link(nT1, nT3);
	node_link(nT1, nT4);
	node_link(nT2, nT5);
	node_link(nT2, nT6);


	grPermP->root=nT0;

	// outputs the test graph as .dot
	fpT = fopen("graphPermP.dot", "w");
	graph_fprint(fpT, grPermP);
	fclose(fpT);

	// outputs the test graph as .graphbin (binary dump)
	fpTb = fopen("graphPermP.graphbin", "w");
	graph_to_file(grPermP, fpTb);
	fclose(fpTb);

	graph_free(grPermP);

	// Creates a (simple) graph for testings with permutations
	int nPermT=13;
	graph_t* grPermT = graph_alloc(nPermT);

	nT0=node_list_append(&grPermT->nodes, 0);
	nT1=node_list_append(&grPermT->nodes, 1);
	nT2=node_list_append(&grPermT->nodes, 2);
	nT3=node_list_append(&grPermT->nodes, 3);
	nT4=node_list_append(&grPermT->nodes, 4);
	nT5=node_list_append(&grPermT->nodes, 5);
	nT6=node_list_append(&grPermT->nodes, 6);
	nT7=node_list_append(&grPermT->nodes, 7);
	nT8=node_list_append(&grPermT->nodes, 8);
	nT9=node_list_append(&grPermT->nodes, 9);
	node_t* nT10=node_list_append(&grPermT->nodes, 10);
	node_t* nT11=node_list_append(&grPermT->nodes, 11);
	node_t* nT12=node_list_append(&grPermT->nodes, 12);

	nT0->symb=8;
	nT1->symb=8;
	nT2->symb=8;
	nT3->symb=9;
	nT4->symb=9;//2
	nT5->symb=9;
	nT6->symb=9;//1
	nT7->symb=9;
	nT8->symb=9;
	nT9->symb=8;
	nT10->symb=9;
	nT11->symb=9;
	nT12->symb=9;

	node_link(nT0, nT1);
	node_link(nT0, nT2);
	node_link(nT1, nT3);
	node_link(nT1, nT4);
	node_link(nT2, nT5);
	node_link(nT2, nT6);

	node_link(nT1, nT7);
	node_link(nT1, nT8);
	node_link(nT0, nT9);
	node_link(nT9, nT10);
	node_link(nT9, nT11);
	node_link(nT6, nT12);


	grPermT->root=nT0;

	// outputs the test graph as .dot
	fpT = fopen("graphPermT.dot", "w");
	graph_fprint(fpT, grPermT);
	fclose(fpT);

	// outputs the test graph as .graphbin (binary dump)
	fpTb = fopen("graphPermT.graphbin", "w");
	graph_to_file(grPermT, fpTb);
	fclose(fpTb);

	graph_free(grPermT);

}

vsize_t min(vsize_t a, vsize_t b){
	if (a<b) return a; else return b;
}

int isoUllman(graph_t* grPattern, graph_t* grToTest){
	if (optionVerbose){
		printf("Options are : p %d, t %d, nThreads %d, ", wP, wT, nThreads);

		if (optionInfo) printf("Info ");
		if (optionMCS) printf("MCS ");
		if (optionMCSByPattern) printf("MCSByPattern ");
		if (optionNoPerm) printf("NoPerm ");
		if (optionCheckSymb) printf("CheckSymbols ");
		if (optionCount) printf("Count ");
		if (optionRedInt) printf("ReductionInterval ");
		if (optionRec) printf("Recursive ");
		if (optionMultiThreaded) printf("MultiThreaded ");
		if (optionForceRoots) printf("ForceRoots ");
		if (optionIsoOnly) printf("IsoOnly ");
		if (optionExport) printf("Export ");
		if (optionOutSmall) printf("OutSmall ");
		if (optionDebug) printf("Debug ");
		if (optionQuiet) printf("Quiet ");
		if (optionVerbose) printf("Verbose ");
		printf("\n");
	}
// 	if (optionCheckSymb) printf("CheckSymbols ");
  
	//Initializing M0:
	vsize_t nToTest = grToTest->nodes.count;
	vsize_t nPattern = grPattern->nodes.count;

// 	printf("nP: %d, nT: %d\n", nPattern, nToTest);

	if ((!optionMCS && nToTest < nPattern) || nToTest == 0 || nPattern == 0){
		// Pattern is larger that the graph to test
		return 0;
	}

	char* M0=calloc(nToTest*nPattern, sizeof(char)); //initializes them to 0
	node_list_t* listT = &(grToTest->nodes);
	node_list_t* listP = &(grPattern->nodes);
	vsize_t i=0;
	vsize_t j=0;

	for(i=0; i<nToTest; i++){
		node_t* nTi = node_list_item(listT, i);

// 		printf("i:%d, id: %d\n", i, (int) nTi->listid);
// 		if (i != nTi->listid) printf("Oops.");

		vsize_t nTiIn=nTi->fathers_nb;
		vsize_t nTiOut=nTi->children_nb;


		for(j=0; j<nPattern; j++){
			node_t* nPj = node_list_item(listP, j);
			vsize_t nPjIn=nPj->fathers_nb;
			vsize_t nPjOut=nPj->children_nb;

//			printf("M: j=%d %d, i=%d %d\n", j+1, (int) nPj->symb, i+1, (int) nTi->symb);
//			printf("%d >= %d && %d >= %d?\n", nTiIn, nPjIn, nTiOut, nPjOut);
//
//			printf("M: j=%d, (%d, %d)\n", j+1, nPjIn, nPjOut);
//			printf("M: i=%d, (%d, %d)\n", i+1, nTiIn, nTiOut);

			// nPj->symb == nTi->symb : is it clever with reductions ? results might be different (slightly without reductions)
			// but it increases (a lot) performances
			if ((!optionCheckSymb || nPj->symb == nTi->symb) && (optionMCS || (nTiIn >= nPjIn && nTiOut >= nPjOut))){
				M0[i*nPattern+j]=1;

				if (optionForceRoots){
					char c1 = nPj==grPattern->root;
					char c2 = nTi==grToTest->root;

					if ((c1 || c2) && (!c1 || !c2)){
						M0[i*nPattern+j]=0;
					}
				}
			}
		}
	}

	char assignedPattern[nPattern];
	char assignedToTest[nToTest];

	for (i=0; i<nPattern; i++){
		assignedPattern[i]=1; //0 assigned, 1 not assigned, unreachable, 2+ not assigned, reachable
	}

	for (i=0; i<nToTest; i++){
		assignedToTest[i]=1;
	}

	//Initializing F
	vsize_t F[2*nPattern];
	vsize_t Fmax=0;

	if (optionMCS) maxFound=0;
// 	debugPrintM(M0, nPattern, nToTest);
	int ret = backtrack(grPattern, grToTest, M0, 0, nPattern, nToTest, min(nPattern, nToTest), F, Fmax, assignedPattern, assignedToTest, 0, listP, listT, optionOnlyInduced);
	if (optionMCS) printf("MaxFound: %d, ", maxFound);

	free(M0);

	return ret;
}

void debugPrintF(vsize_t* F, vsize_t Fmax){
//	printf("F: j -- i\n");
	int fm;
	for(fm=0; fm<Fmax; fm+=2){
		printf("%d -- %d, ", F[fm+1], F[fm]);
	}
	printf("\n");
}

void debugPrintM(char* M0, vsize_t nPattern, vsize_t nToTest){
	printf("M:\n");
	int i, j;
	for (i=0; i<nToTest;i++){
		for (j=0; j<nPattern;j++){
			printf("%d", M0[i*nPattern+j]);
			printf(" ");
		}
		printf("\n");
	}
}

void debugPrintAssigned(char* assignedPattern, char* assignedToTest, vsize_t nPattern, vsize_t nToTest){
	vsize_t k;

	printf("assignedP :");
	for (k=0; k<nPattern; k++){
		printf("%d ", assignedPattern[k]);
	}
	printf("\n");

	printf("assignedT :");
	for (k=0; k<nToTest; k++){
		printf("%d ", assignedToTest[k]);
	}
	printf("\n");
}

int backtrack(graph_t* grPattern, graph_t* grToTest, char* M0, vsize_t j, vsize_t nPattern, vsize_t nToTest, vsize_t limit, vsize_t* F, vsize_t Fmax, char* assignedPattern, char* assignedToTest, vsize_t lastAssignedPatternPlusOne, node_list_t* listP, node_list_t* listT, char optionOnlyInduced){
	int ret=0;

// 	if (optionDebug) printf("processing j=%d\n", j);
// 	fflush(stdout);

// 	debugPrintF(F, Fmax);
	if (j>=limit){ //there is isomorphism : output it and move on (return)
// 		printf("Found\n");
// 		debugPrintF(F, Fmax);
		return 1;
	}
	else{
		int i;
		int lmax;
		int lmin;
		// in case of search of MCS, every node in graphPattern will not necessarily be matched, so we need to test each of them
		if (optionMCS) lmax=nPattern; else lmax=1;
		if (optionMCS) lmin=0; else lmin=0;//lastAssignedPatternPlusOne
		int l;

		for (l=lmin; l<lmax; l++){
			if (j==0) maxPatternFound=0;

			for(i=0; i<nToTest;i++){
				if (!optionMCS) l=j;

//				if (l==12 && i==104){
//					printf("12104d\n");
//					debugPrintF(F, Fmax);
//					debugPrintAssigned(assignedPattern, assignedToTest, nPattern, nToTest);
//					printf("aP:%d, aT:%d, M:%d\n", assignedPattern[l], assignedToTest[i], M0[i*nPattern + l]);
//					printf("12104f\n");
//				}
// 				printf("(i, j), M: (%d, %d), %d\n", i, j, M0[i*nPattern + l]);

				if ((!optionMCS || j==0 || (assignedPattern[l]>=2 && assignedToTest[i]>=2)) && M0[i*nPattern + l]==1){ // forearch i in G , Mij=1 :
					if (optionMCS && maxFound < j+1) {
						maxFound = j+1;
						if (optionVerbose) printf("maxFound: %d\n", maxFound);
					}
					if (optionMCSByPattern && maxPatternFound < j+1) {
						maxPatternFound = j+1;
//							if (optionVerbose) printf("Node l=%d, maxPatternFound: %d\n",l, maxPatternFound);
					}

					// F=F (Union) {(i,j)}
					F[Fmax]=i;
					F[Fmax+1]=l;
					Fmax+=2;

					// Update M -> M'
					char* Mp=malloc(nToTest*nPattern*sizeof(char));
					memcpy(Mp, M0, nPattern*nToTest);

					node_t* nPl;
					node_t* nTi;
					nPl = node_list_item(listP, l);
					nTi = node_list_item(listT, i);

					int k;
					if (optionMCS){
						for (k=0; k<nPl->children_nb; k++){
							vsize_t s = nPl->children[k]->list_id;
							if (assignedPattern[s]!=0) assignedPattern[s]++;
						}

						for (k=0; k<nTi->children_nb; k++){
							vsize_t s = nTi->children[k]->list_id;
							if (assignedToTest[s]!=0) assignedToTest[s]++;
						}
					}

//					printf("l: %d, i: %d\n", l, i);

					// Other patterns can't associate with i anymore :

					for(k=0; k<=nPattern - 1; k++){
						if (k!=l) Mp[i*nPattern+k]=0;
					}

					// Other toTest can't associate with l anymore
					for(k=0; k<=nToTest - 1; k++){
						if (k!=i) Mp[k*nPattern+l]=0;
					}

					assignedPattern[l]=0;
					assignedToTest[i]=0;

					// forbids permutations :
					if (optionNoPerm){
						forbidPerm(grPattern, grToTest, Mp, l, nPattern, nToTest, F, i);
					}

// 					debugPrintF(F, Fmax);
// 					debugPrintAssigned(assignedPattern, assignedToTest, nPattern, nToTest);
//					if (l==14 && i==103)
// 					debugPrintM(Mp, nPattern, nToTest);
	//				printf("j: %d\n", j);

					if (j+1>=limit || forwardChecking(grPattern, grToTest, Mp, l, nPattern, nToTest, F, Fmax, assignedPattern, assignedToTest, listP, listT, optionOnlyInduced)) {
// 						printf("forward\n");
// 						debugPrintM(Mp, nPattern, nToTest);
	//					printf("p%d ", j);
						ret+=backtrack(grPattern, grToTest, Mp, j+1, nPattern, nToTest, limit, F, Fmax, assignedPattern, assignedToTest, l+1, listP, listT, optionOnlyInduced);
						if (ret != 0 && !optionCount) return ret;
					}

					free(Mp);

					// F=F - {(i,j)}
					Fmax-=2;

					if (optionMCS){
						for (k=0; k<nPl->children_nb; k++){
							vsize_t s = nPl->children[k]->list_id;
							if (assignedPattern[s]!=1) assignedPattern[s]--;
						}

						for (k=0; k<nTi->children_nb; k++){
							vsize_t s = nTi->children[k]->list_id;
							if (assignedToTest[s]!=1) assignedToTest[s]--;
						}
					}

					if (j!=0){
						assignedPattern[l]=2;
						assignedToTest[i]=2;
					}
					else{
						assignedPattern[l]=1;
						assignedToTest[i]=1;
					}
				}
			}

//			if (j==0) printf("Node l=%d, maxPatternFound final: %d\n",l, maxPatternFound);
		}
	}

	return ret;
}

void forbidPerm(graph_t* grPattern, graph_t* grToTest, char* Mp, vsize_t j, vsize_t nPattern, vsize_t nToTest, vsize_t* F, int i){
	node_list_t* listP = &(grPattern->nodes);
	node_list_t* listT = &(grToTest->nodes);
	node_t* nPj;
	node_t* nTi;
	nPj = node_list_item(listP, j);
	nTi = node_list_item(listT, i);
	vsize_t kFatherP;
	vsize_t kFatherT;
	vsize_t kChildP;
	vsize_t kChildT;
	node_t* nChildP;
	node_t* nChildT;
	int kChildj;
	int kChildi;
	vsize_t listidChildP;
	vsize_t listidChildT;
	vsize_t listidFatherP;
	vsize_t listidFatherT;
	vsize_t lastChild;
	node_t* nFatherP;
	node_t* nFatherT;

	for (kFatherP=0; kFatherP<nPj->fathers_nb; kFatherP++){
		nFatherP=nPj->fathers[kFatherP];

		if (nFatherP->list_id < j){ // then nFatherP is already associated with a father of i
			nFatherT = node_list_item(listT, F[nFatherP->list_id*2]);
			kChildj=-1;
			kChildi=-1;
			for (kChildP=0; kChildP<nFatherP->children_nb; kChildP++){
				listidChildP=nFatherP->children[kChildP]->list_id;

				if (nFatherP->children[kChildP] == nPj){
					kChildj=kChildP;
				}

				for (kChildT=0; kChildT<nFatherT->children_nb; kChildT++){
					listidChildT=nFatherT->children[kChildT]->list_id;

					if (kChildi == -1 && nFatherT->children[kChildT] == nTi){
						kChildi=kChildT;
					}

					if (kChildj == -1){
						if (kChildi != -1 && kChildT > kChildi){
							Mp[listidChildT*nPattern+listidChildP]=0;
						}
					}

					if (kChildj != -1){
						if (kChildi == -1 || kChildT < kChildi){
							Mp[listidChildT*nPattern+listidChildP]=0;
						}
					}
				}
			}
		}
		listidFatherP=nFatherP->list_id;

		for (kFatherT=0; kFatherT<nTi->fathers_nb; kFatherT++){
			nFatherT = nTi->fathers[kFatherT];
			listidFatherT=nFatherT->list_id;

			if (Mp[listidFatherT*nPattern+listidFatherP] == 1){
				lastChild=0;
				for (kChildP=0; kChildP<nFatherP->children_nb; kChildP++){
					if (kChildP < j){ // then kChildj already in an association
						nChildP=nFatherP->children[kChildP];
						listidChildP=nChildP->list_id;
						nChildT=node_list_item(listT, F[listidChildP*2]);

						// the associated in T is a child of nFatherT ?
						for (kChildT=0; kChildT<nFatherT->children_nb; kChildT++){
							if (nFatherT->children[kChildT] == nChildT){ // then yes
								// checks that the *child number* in T is greater thant the lattest
								if (kChildT >= lastChild){
									// then this is all ok for this child, next.
									lastChild=kChildT;
									break;
								}
								else{
									// problem : if nFatherP and nFatherT were associated, there would be a permutation
									// so they can't
									Mp[listidFatherT*nPattern+listidFatherP]=0;
									break;
								}
							}
						}
						if (Mp[listidFatherT*nPattern+listidFatherP]==0) break;
					}
				}
			}
		}
	}
}

int forwardChecking(graph_t* grPattern, graph_t* grToTest, char* Mp, vsize_t j, vsize_t nPattern, vsize_t nToTest, vsize_t* F, vsize_t Fmax, char* assignedPattern, char* assignedToTest, node_list_t* listP, node_list_t* listT, char optionOnlyInduced){
  // 	printf("begin forward\n");
//   debugPrintM(Mp, nPattern, nToTest);
//   debugPrintF(F, Fmax);

  vsize_t k;
  vsize_t l;
  for (k=0; k<nToTest; k++){
    for (l=0; l<nPattern; l++){ //for (l=j+1; l<nPattern; l++){
      if(assignedToTest[k]!=0 && assignedPattern[l]!=0 && Mp[k*nPattern + l]){
	node_t* nPl = node_list_item(listP, l);
	node_t* nTk = node_list_item(listT, k);
	vsize_t fm, v, w;

	fm=Fmax-2;
	v=F[fm];
	w=F[fm+1];
	node_t* nPw = node_list_item(listP, w);
	node_t* nTv = node_list_item(listT, v);

	// booleans : 1 (true), 0 (false)
	// K(bool) : 1 (known), 0 (unknown)
	char ekv=0;
	char Kekv=0;
	char evk=0;
	char Kevk=0;
	char elw=0;
	//				char Kelw=0;
	char ewl=0;
	//				char Kewl=0;
	//				char flk=0;
	//				char Kflk=0;



	if (!optionOnlyInduced){
	  //  Checks if : ((k, v) and (l -- k)) => (l, w),  and  ((v, k) and (l -- k)) => (w, l)
	  //  "Bool" cp1 = !ekv || elw;
	  //  "Bool" cp2 = !evk || ewl;
	  //  Attention, les notations sont inversées par rapport au chapitre "algo"
	  //  Ici :
	  //  P : w, l
	  //  T : v, k
	  char cp1=0;
	  char cp2=0;
	  char Cp; // Cp=cp1 || cp2
	  elw=E(nPl, nPw);
	  ekv=E(nTk, nTv);
	  ewl=E(nPw, nPl);
	  evk=E(nTv, nTk);
	  cp1 = ekv || !elw; // instead of !ekv || elw because of the inversion
	  cp2 = evk || !ewl; // instead of !evk || ewl because of the inversion
	  Cp=!(cp1 && cp2);
// 	  printf("cp1: (k, l): (%d, %d), (v, w): (%d, %d), P:%d, T:%d\n", k, l, v, w, ekv, elw);
// 	  printf("cp2: (k, l): (%d, %d), (v, w): (%d, %d), P:%d, T:%d\n", k, l, v, w, evk, ewl);
	  if (Cp){
	    Mp[k*nPattern + l]=0;
	  }
	}
	else{
	//        Checks if : ((k, v) and (l -- k)) iff (l, w),  and  ((v, k) and (l -- k)) iff (w, l)
	//        "Bool" c1 = (ekv && elw) || (!ekv && !elw);
	//        "Bool" c2 = (evk && ewl) || (!evk && !ewl);

	char c1=0;
	char c2=0;

	char C; // C=!(c1 && c2)=!c1 || !c2
	// C=1 iff c1=0 or c2=0

	//				Determining c1, beginning by the second term
	// edge (l, w) in P ?
	elw=E(nPl, nPw);
	//				Kelw=1;

	if (!elw){
	  // edge (k, v) in T ?
	  ekv=E(nTk, nTv);
	  Kekv=1;

	  if (!ekv) {
	    c1=1;
	  }
	}

	if (!c1){ // c1 still unknown
	  //elw is (always) known
	  if (elw){
	    if (!Kekv){
	      // edge (k, v) in T ?
	      ekv=E(nTk, nTv);
	      Kekv=1;
	    }

	    if (ekv){
	      c1=1;
	    }
	  }
	}

	//				Determining c2, beginning by the second term, only if c1 is true
	if (c1){
	  // edge (w, l) in P ?
	  ewl=E(nPw, nPl);
	  //					Kewl=1;

	  if (!ewl){
	    // edge (v, k) in T ?
	    evk=E(nTv, nTk);
	    Kevk=1;

	    if (!evk) {
	      c2=1;
	    }
	  }

	  if (!c2){ // c2 still unknown
	    //ewl is (always) known
	    if (ewl){
	      if (!Kevk){
		// edge (v, k) in T ?
		evk=E(nTv, nTk);
		Kevk=1;
	      }

	      if (evk){
		c2=1;
	      }
	    }
	  }
	}

	// C=1 iff c1=0 or c2=0
	C=!(c1&&c2);

	if (C){
	  Mp[k*nPattern + l]=0;
	}
	}
      }
    }
  }

  //	debugPrintM(Mp, nPattern, nToTest);

  // exists l >= j + 1 / foreach k, Mk,l = 0 ?
  if (!optionMCS){
    for (l=j+1; l<nPattern; l++){
      char eM=0; // exists l / M[k][l]=1 ?

      for (k=0; k<nToTest; k++){
	if (Mp[k*nPattern + l]==1) {
	  eM=1;
	  break;
	}
      }

      if (!eM){
	//			printf("0\n");
	return 0;
      }
    }
  }
  else {
    for (l=0; l<nPattern; l++){
      for (k=0; k<nToTest; k++){
	if (assignedPattern[l]!=0 && assignedToTest[k]!=0 && Mp[k*nPattern+l]==1){
	  return 1;
	}
      }
    }
    return 0;
  }
  //	printf("1\n");
  return 1;
}

//char Flk(vsize_t l, vsize_t k, vsize_t* F, vsize_t Fmax){
//	return 1;
//
//	vsize_t fm2, a, b;
//
//	// l <--> k ?
//	for(fm2=0; fm2<=Fmax-1; fm2+=2){
//		a=F[fm2];
//		b=F[fm2+1];
//
//		if ((a==k && b==l)){//(a==l && b==k) ||
////			printf("yop %d %d %d %d\n", a, b, l, k);
//			return 1;
//		}
//	}
//
//	return 0;
//}

char E(node_t* n1, node_t* n2){
	vsize_t t;

	// edge (n1, n2) ?
	for (t=0; t<n1->children_nb; t++){
		if (n1->children[t] == n2){
			return 1;
		}
	}

	return 0;
}

char* BFS2(graph_t* inputGraph, vsize_t vroot, vsize_t R){
	char* matrix = calloc(R*R, sizeof(char));

	//all inputgraph nodes to unexplored(0):
	node_list_t* listI = &(inputGraph->nodes);

	vsize_t i;
	node_t* nI;

	for (i=0; i<listI->count; i++){
		nI = node_list_item(listI, i);
		nI->explored=0; //unexplored
	}

	//keep track of matches inputNode <-> node (pointers) and acts as a queue
	node_t** nodeTrack=malloc(R*2*sizeof(node_t*));
	vsize_t nnT=0;

	graph_t* graph = graph_alloc(R);
	vsize_t s=0;

	nI = node_list_item(listI, vroot);
//	nI=inputGraph->root;
	nI->explored=1; // under exploration

//	printf("\nroot: %d\n", (int)nI->node_id);

	//adds the root to the graph and track
	node_t* nG=node_list_append(&graph->nodes, s);
	s++;
	// copies nI in graph, without the parent / child stuff
	nG->explored=nI->explored;
	nG->node_id=nI->node_id;
	nG->symb=nI->symb;
//	memcpy(nG, nI, sizeof(node_t));
//	MY_FREE(nG->fathers);
//	MY_FREE(nG->children);

	//adds the track
	nodeTrack[nnT]=nI;
	nodeTrack[nnT+1]=nG;
	nnT+=2;

	node_t* child;
	vsize_t k;
	vsize_t nnTmax;
	char IsChild=1;

	while(s<R && IsChild){
		IsChild=0;
		nnTmax=nnT;

		for (i=0; i<nnTmax; i+=2){
			if (s<R){
				nI = nodeTrack[i];
				if (nI->explored==1){ //under exploration : put children under exploration and itself explored
					nI->explored=2; //explored

					for (k=0; k<nI->children_nb; k++){
						child=nI->children[k];

						if (s<R && child->explored==0){
							IsChild=1;
							child->explored=1;
							//adds the child to the graph and track
							node_t* nG=node_list_append(&graph->nodes, s);
							s++;
							// copies nI in graph, without the parent / child stuff
							nG->explored=child->explored;
							nG->node_id=child->node_id;
							nG->symb=child->symb;
//							memcpy(nG, child, sizeof(node_t));
//							MY_FREE(nG->fathers);
//							MY_FREE(nG->children);

							//adds the track
							nodeTrack[nnT]=child;
							nodeTrack[nnT+1]=nG;
							nnT+=2;

//							printf("explored: %d, father: %d\n", (int) child->node_id, (int) nI->node_id);
						}
					}
				}
			}
			else{
				break;
			}
		}
	}

	if (s!=R){
		graph_free(graph);
//		printf("error\n");
		return NULL;
	}

	// now we need to :
	// -> create the edges for nodes in inputGraph and explored (or under exploration) which children also are explored (or under expl)

	if (optionCheckSymb){
		for (i=0; i<nnT; i+=2){
			nI=nodeTrack[i];
			matrix[(i/2)*R+(i/2)]=nI->symb;
		}
	}

	vsize_t j;

	for (i=0; i<nnT; i+=2){
		nI=nodeTrack[i];
		nG=nodeTrack[i+1];

//		printf("nI: %p, nG: %p\n", nI, nG);

		for (k=0; k<nI->children_nb; k++){
			child=nI->children[k];

			if (child->explored!=0){
				//find which nodeTrack it is

				for (j=0; j<nnT; j+=2){
					if (nodeTrack[j]==child){
						matrix[(i/2)*R+j/2]=1;
//						node_link(nG, nodeTrack[j+1]);
						break;
					}
				}
			}
		}
	}

//	printf("s: %d\n", s);

//	node_list_t* list = &(graph->nodes);
//	node_t* root = node_list_item(list, 0);
//	graph->root=root;

	graph_free(graph);
	free(nodeTrack);
	return matrix;
}

graph_t* BFS_gba(graph_t* inputGraph, vsize_t vroot, vsize_t R){
	//all inputgraph nodes to unexplored(0):
	node_list_t* listI = &(inputGraph->nodes);

	vsize_t i;
	node_t* nI;

	for (i=0; i<listI->count; i++){
		nI = node_list_item(listI, i);
		nI->explored=0; //unexplored
	}

	//keep track of matches inputNode <-> node (pointers) and acts as a queue
	node_t** nodeTrack=malloc(R*2*sizeof(node_t*));
	vsize_t nnT=0;

	graph_t* graph = graph_alloc(R);
	vsize_t s=0;

	nI = node_list_item(listI, vroot);
//	nI=inputGraph->root;
	nI->explored=1; // under exploration

//	printf("\nroot: %d\n", (int)nI->node_id);

	//adds the root to the graph and track
	node_t* nG=node_list_append(&graph->nodes, s);
	s++;
	// copies nI in graph, without the parent / child stuff
	nG->explored=nI->explored;
	nG->node_id=nI->node_id;
	nG->symb=nI->symb;
//	memcpy(nG, nI, sizeof(node_t));
//	MY_FREE(nG->fathers);
//	MY_FREE(nG->children);

	//adds the track
	nodeTrack[nnT]=nI;
	nodeTrack[nnT+1]=nG;
	nnT+=2;

	node_t* child;
	vsize_t k;
	vsize_t nnTmax;
	char IsChild=1;

	while(s<R && IsChild){
		IsChild=0;
		nnTmax=nnT;

		for (i=0; i<nnTmax; i+=2){
			if (s<R){
				nI = nodeTrack[i];
				if (nI->explored==1){ //under exploration : put children under exploration and itself explored
					nI->explored=2; //explored

					for (k=0; k<nI->children_nb; k++){
						child=nI->children[k];

						if (s<R && child->explored==0){
							IsChild=1;
							child->explored=1;
							//adds the child to the graph and track
							node_t* nG=node_list_append(&graph->nodes, s);
							s++;
							// copies nI in graph, without the parent / child stuff
							nG->explored=child->explored;
							nG->node_id=child->node_id;
							nG->symb=child->symb;
//							memcpy(nG, child, sizeof(node_t));
//							MY_FREE(nG->fathers);
//							MY_FREE(nG->children);

							//adds the track
							nodeTrack[nnT]=child;
							nodeTrack[nnT+1]=nG;
							nnT+=2;

//							printf("explored: %d, father: %d\n", (int) child->node_id, (int) nI->node_id);
						}
					}
				}
			}
			else{
				break;
			}
		}
	}

	// now we need to :
	// -> create the edges for nodes in inputGraph and explored (or under exploration) which children also are explored (or under expl)

	vsize_t j;

	for (i=0; i<nnT; i+=2){
		nI=nodeTrack[i];
		nG=nodeTrack[i+1];

//		printf("nI: %p, nG: %p\n", nI, nG);

		for (k=0; k<nI->children_nb; k++){
			child=nI->children[k];

			if (child->explored!=0){
				//find which nodeTrack it is

				for (j=0; j<nnT; j+=2){
					if (nodeTrack[j]==child){
						node_link(nG, nodeTrack[j+1]);
						break;
					}
				}
			}
		}
	}

//	printf("s: %d\n", s);

	node_list_t* list = &(graph->nodes);
	node_t* root = node_list_item(list, 0);
	graph->root=root;

	free(nodeTrack);

	if (s==R){
		return graph;
	}
	else{
		graph_free(graph);
		return NULL;
	}
}

int computeInterval(graph_t* inputGraph, node_t* head, node_t** intervals, int nInterval){
//	printf("c1\n");
	node_list_t* listI = &(inputGraph->nodes);
	int sizeI=listI->count;
//	printf("c2\n");

	int maxI=0;
	intervals[nInterval*sizeI+0]=head;
	maxI++;
	node_t* nI;
	int i;
	int j;
	int p;
//	printf("c3\n");
	int pOk=0;
	int added=1;
//	char alreadyIn=0;

//	printf("head : %d\n", (int) head->node_id);

	while (added==1){
		added=0;

		for (i=0; i<listI->count; i++){
			nI = node_list_item(listI, i);
//			printf("i: %d ", i);

			// is it not the root ?
			if (nI != inputGraph->root){
//				printf("noth ");
				// is it already in an interval ?
				if (isNodeIn(nI, intervals, nInterval*sizeI, maxI)){
//				if (nI->explored!=0){
//					printf("alr\n");
					continue;
				}

//				printf("noalr ");
				// do "all edges entering nI leave nodes in interval" ?
				// all parents must be in interval
				for (p=0; p<nI->fathers_nb; p++){
					pOk=0;

					// is father in interval ?
					for (j=0; j<maxI; j++){
						if (nI->fathers[p] == intervals[nInterval*sizeI+j]){
							// yes it is
//							printf("fatherIn ");
							pOk=1;
							break;
						}

//						printf("father : %d", (int) nI->fathers[p]->node_id);
					}

					// not it was not
					if (pOk==0) break;
				}

				if (pOk==0){
//					printf("noAdd\n");
					continue;
				}

				// yes it is ok :
				// add i to interval
				intervals[nInterval*sizeI+maxI]=nI;
				maxI++;
				added=1;
				nI->explored=2; //explored
//				printf("%d\n", (int) nI->node_id);
//				printf("Add\n");
			}
		}
	}

	return maxI;
}

char isNodeIn(node_t* node, node_t** intervals, int nRow, int maxI){
	int j;

	for (j=0; j<maxI; j++){
		if (node == intervals[nRow+j]){
			return 1;
		}
	}

	return 0;
}

graph_t* reduceInterval(graph_t* inputGraph){
	node_list_t* listI = &(inputGraph->nodes);
	graph_t* reducedGraph=graph_alloc(listI->count);
	node_list_t* listR = &(reducedGraph->nodes);

//	node_t*** intervals=malloc(listI->count*listI->count*sizeof(node_t*));
//	printf("s:%d, node_t*: %d, char: %d\n", listI->count, sizeof(node_t*), sizeof(char));
//	node_t* intervals[listI->count][listI->count];
		node_t** intervals=malloc(listI->count*listI->count*sizeof(node_t*)); // 2 "dimension array"
//	node_t* intervals[500][1200];
//	node_t* intervals[800][1200];

	node_t* headers[listI->count];
	int maxH=0;
	int currH=0;
	headers[0]=inputGraph->root;
	maxH++;
	int nIntervals=0;
	int maxI[listI->count];
	int i, j;
	node_t* nI;
	node_t* n;

	for (i=0; i<listI->count; i++){
		nI = node_list_item(listI, i);
		nI->explored=0; //unexplored
	}

	while(maxH > currH){
//		printf("nIntervals: %d\n", nIntervals);
		maxI[nIntervals]=computeInterval(inputGraph, headers[currH], intervals, nIntervals);
//		printf("maxI[nInt]: %d\n", maxI[nIntervals]);

		// add in H all nodes not i previous intervals (explored!) and who has a direct ancestor in last interval
		for (i=0; i<listI->count; i++){
			nI = node_list_item(listI, i);

			if (nI->explored==0 && !isNodeIn(nI, headers, 0, maxH)){
				for (j=0; j<nI->fathers_nb; j++){
					if (isNodeIn(nI->fathers[j], intervals, nIntervals*listI->count, maxI[nIntervals])){
						// add nI to headers:
						headers[maxH]=nI;
//						printf("Hadded: %d\n", (int) nI->node_id);
						maxH++;
						break;
					}
				}
			}
		}
		n=node_list_append(listR, nIntervals);
		n->node_id=nIntervals;
		n->symb=9;

		currH++;
		nIntervals++;
	}


int c, k;
node_t* n2;
	for (i=0; i<nIntervals; i++){
		for (j=0; j<maxI[i]; j++){
			for (c=0; c<intervals[i*listI->count+j]->children_nb; c++){
				for (k=0; k<nIntervals; k++){
					if (isNodeIn(intervals[i*listI->count+j]->children[c], intervals, k*listI->count, maxI[k])){
						n = node_list_item(listR, i);
						n2 = node_list_item(listR, k);
						if (!E(n, n2) && n!=n2) node_link(n, n2);
					}
				}
			}
		}
	}

	reducedGraph->root=node_list_item(listR, 0);

//	printf("nIntervals: %d\n", nIntervals);
	return reducedGraph;
}
